// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/local_files.hpp"

#include "gdp/clock.hpp"
#include "gdp/file_transfer.hpp"
#include "gdp/framing.hpp"
#include "log.hpp"

#include <algorithm>
#include <filesystem>
#include <system_error>

namespace spectre {

namespace {

constexpr size_t kChunk = 256 * 1024;
// File bytes sent but not yet acknowledged, per answer; as for uploads.
constexpr uint64_t kInFlight = 4ull << 20;

std::filesystem::path fs_path(const std::string &utf8) {
	return std::filesystem::path(std::u8string(utf8.begin(), utf8.end()));
}

std::string utf8_path(const std::filesystem::path &path) {
	std::u8string s = path.u8string();
	return std::string(s.begin(), s.end());
}

} // namespace

struct LocalFiles::Job {
	uint64_t id = 0;
	std::unique_ptr<gdp::Stream> stream;
	std::ifstream in;
	uint64_t size = 0;   // bytes of the range
	uint64_t header = 0; // the StreamOpen and FileReply frames ahead of them
	uint64_t sent = 0;
	uint64_t acked = 0;
};

LocalFiles::LocalFiles(OpenStream open_stream, std::function<uint64_t()> now_us)
	: open_stream_(std::move(open_stream)),
	  now_us_(now_us ? std::move(now_us) : std::function<uint64_t()>(gdp::monotonic_us)) {}

LocalFiles::~LocalFiles() {
	cancel_all();
}

gdp::session::FileList LocalFiles::set_list(const std::vector<std::string> &paths) {
	uint64_t now = now_us_();
	auto latest = lists_.find(list_id_);
	if (latest != lists_.end()) {
		latest->second.replaced_us = now;
	}
	list_id_++;
	List &list = lists_[list_id_];
	list.files = gdp::LocalFileList::build(list_id_, paths, true);
	list.last_used_us = now;
	has_list_ = list.files.size() > 0;
	expire_lists(now);
	return list.files.listing();
}

void LocalFiles::expire_lists(uint64_t now_us) {
	std::vector<std::pair<uint64_t, uint64_t>> earlier; // (last active, id)
	std::vector<uint64_t> gone;
	for (const auto &[id, list] : lists_) {
		if (list.replaced_us == 0) {
			continue;
		}
		uint64_t active = std::max(list.replaced_us, list.last_used_us);
		if (now_us - active >= kKeptListUs) {
			gone.push_back(id);
		} else {
			earlier.emplace_back(active, id);
		}
	}
	if (earlier.size() > kKeptLists) {
		std::sort(earlier.begin(), earlier.end());
		for (size_t i = 0; i < earlier.size() - kKeptLists; i++) {
			gone.push_back(earlier[i].second);
		}
	}
	for (uint64_t id : gone) {
		lists_.erase(id);
	}
}

LocalFiles::List *LocalFiles::use_list(uint64_t list_id) {
	uint64_t now = now_us_();
	expire_lists(now);
	auto it = lists_.find(list_id);
	if (it == lists_.end()) {
		return nullptr;
	}
	it->second.last_used_us = now;
	return &it->second;
}

uint64_t LocalFiles::add_share(const std::string &path, bool include_hidden, std::string *name) {
	std::error_code ec;
	std::filesystem::path p = fs_path(path);
	if (!std::filesystem::is_directory(p, ec)) {
		return 0;
	}
	std::filesystem::path canonical = std::filesystem::canonical(p, ec);
	if (!ec) {
		p = canonical;
	}
	if (name->empty()) {
		*name = utf8_path(p.filename());
	}
	if (!gdp::valid_file_name(*name)) {
		*name = "Shared folder"; // "/" or a name the host would refuse
	}
	uint64_t id = next_share_++;
	shares_[id] = Share{utf8_path(p), include_hidden};
	return id;
}

void LocalFiles::answer(const gdp::session::FileFetch &fetch) {
	std::unique_ptr<gdp::Stream> stream = open_stream_();
	if (!stream) {
		return; // the host gives up on it after its deadline
	}
	gdp::session::FileOpen open;
	open.mutable_answer()->set_fetch_id(fetch.fetch_id());
	gdp::session::StreamOpen stream_open;
	stream_open.set_kind(gdp::kStreamKindFile);
	stream_open.set_params(open.SerializeAsString());
	stream->send_message(stream_open);

	std::string path;
	std::string name;
	bool directory = false;
	std::vector<gdp::session::FileListing> frames;
	if (fetch.share_id() != 0) {
		auto share = shares_.find(fetch.share_id());
		bool include_hidden = share != shares_.end() && share->second.include_hidden;
		path = share == shares_.end() ? std::string()
									  : gdp::resolve_beneath(share->second.folder, fetch.path(), include_hidden);
		gdp::LocalEntry entry;
		if (path.empty() || !gdp::stat_local(path, &entry, fetch.path().empty())) {
			refuse(std::move(stream), gdp::session::FILE_ERROR_GONE);
			return;
		}
		directory = entry.directory;
		name = entry.name;
		if (fetch.listing()) {
			if (!directory) {
				refuse(std::move(stream), gdp::session::FILE_ERROR_GONE);
				return;
			}
			// A shared folder's entries have no index; frames within the budget.
			gdp::session::FileListing frame;
			size_t used = 0;
			for (const gdp::LocalEntry &e : gdp::read_local_folder(path, include_hidden)) {
				gdp::session::FileListEntry le = gdp::to_list_entry(e);
				size_t more = le.ByteSizeLong() + 4;
				if (frame.files_size() > 0 && used + more > gdp::kFileListBudgetBytes) {
					frames.push_back(std::move(frame));
					frame = gdp::session::FileListing();
					used = 0;
				}
				*frame.add_files() = std::move(le);
				used += more;
			}
			frames.push_back(std::move(frame));
			send_listing(std::move(stream), frames);
			return;
		}
	} else {
		List *list = use_list(fetch.list_id());
		if (!list || fetch.index() >= list->files.size()) {
			refuse(std::move(stream), gdp::session::FILE_ERROR_GONE);
			return;
		}
		if (fetch.listing()) {
			if (!list->files.list_folder(fetch.index(), &frames)) {
				refuse(std::move(stream), gdp::session::FILE_ERROR_GONE);
				return;
			}
			send_listing(std::move(stream), frames);
			return;
		}
		path = list->files.path(fetch.index());
		name = list->files.listing().files(static_cast<int>(fetch.index())).name();
		directory = list->files.is_directory(fetch.index());
		// Inside a copied folder, a file that has become a link since it was
		// listed is not followed.
		std::error_code ec;
		if (!list->files.is_top_level(fetch.index()) &&
			std::filesystem::is_symlink(std::filesystem::symlink_status(fs_path(path), ec))) {
			refuse(std::move(stream), gdp::session::FILE_ERROR_READ_FAILED);
			return;
		}
	}
	if (directory) {
		refuse(std::move(stream), gdp::session::FILE_ERROR_GONE);
		return;
	}
	send_file(std::move(stream), path, name, fetch);
}

void LocalFiles::send_reply(gdp::Stream &stream, const gdp::session::FileReply &reply) {
	stream.send_message(reply);
}

void LocalFiles::refuse(std::unique_ptr<gdp::Stream> stream, gdp::session::FileErrorCode code) {
	gdp::session::FileReply reply;
	reply.mutable_refused()->set_code(code);
	send_reply(*stream, reply);
	stream->send(nullptr, 0, true);
	// Dropped here: our side ended with the FIN, so it still goes.
}

void LocalFiles::send_listing(std::unique_ptr<gdp::Stream> stream,
	const std::vector<gdp::session::FileListing> &frames) {
	for (const auto &frame : frames) {
		gdp::session::FileReply reply;
		*reply.mutable_listing() = frame;
		send_reply(*stream, reply);
	}
	stream->send(nullptr, 0, true);
}

void LocalFiles::send_file(std::unique_ptr<gdp::Stream> stream, const std::string &path, const std::string &name,
	const gdp::session::FileFetch &fetch) {
	auto job = std::make_unique<Job>();
	std::filesystem::path p = fs_path(path);
	std::error_code ec;
	uint64_t file_size = std::filesystem::file_size(p, ec);
	if (!ec) {
		job->in.open(p, std::ios::binary);
	}
	if (ec || !job->in) {
		refuse(std::move(stream), gdp::session::FILE_ERROR_READ_FAILED);
		return;
	}
	gdp::LocalEntry entry;
	gdp::stat_local(path, &entry, true);
	uint64_t start = std::min<uint64_t>(fetch.offset(), file_size);
	uint64_t left = file_size - start;
	job->size = fetch.length() == 0 ? left : std::min<uint64_t>(fetch.length(), left);
	job->in.seekg(static_cast<std::streamoff>(start));

	gdp::session::FileReply reply;
	auto *sending = reply.mutable_sending();
	sending->set_name(name);
	sending->set_size(job->size);
	sending->set_modified_unix_ms(entry.modified_unix_ms);
	sending->set_offset(start);
	sending->set_file_size(file_size);
	// What precedes the file's bytes on the stream: the opening frame
	// answer() sent, and this reply.
	gdp::session::FileOpen open;
	open.mutable_answer()->set_fetch_id(fetch.fetch_id());
	gdp::session::StreamOpen stream_open;
	stream_open.set_kind(gdp::kStreamKindFile);
	stream_open.set_params(open.SerializeAsString());
	std::vector<uint8_t> f1, f2;
	gdp::encode_frame(stream_open, &f1);
	gdp::encode_frame(reply, &f2);
	job->header = f1.size() + f2.size();
	stream->send(f2.data(), f2.size(), job->size == 0);
	if (job->size == 0) {
		return; // its FIN went with the reply
	}

	job->id = next_job_++;
	job->stream = std::move(stream);
	Job *j = job.get();
	j->stream->on_data = [](const uint8_t *, size_t) {}; // the host sends nothing on it
	j->stream->on_reset = [this, j](uint64_t) { remove(j); };
	j->stream->on_acked = [this, j](uint64_t total) {
		j->acked = total > j->header ? total - j->header : 0;
		pump(j);
	};
	jobs_[j->id] = std::move(job);
	pump(j);
}

void LocalFiles::pump(Job *job) {
	while (job->sent < job->size && job->sent - std::min(job->acked, job->sent) < kInFlight) {
		size_t n = static_cast<size_t>(std::min<uint64_t>(kChunk, job->size - job->sent));
		std::vector<uint8_t> buf(n);
		job->in.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(n));
		if (static_cast<size_t>(job->in.gcount()) != n) {
			// The file shrank: reset rather than send it short (§7.12).
			SLOG_INFO("files: a file the host is reading changed; resetting it");
			job->stream->reset(0);
			remove(job);
			return;
		}
		job->sent += n;
		bool last = job->sent == job->size;
		job->stream->send(buf.data(), n, last);
		if (last) {
			remove(job); // gracefully: our FIN is in
			return;
		}
	}
}

void LocalFiles::remove(Job *job) {
	jobs_.erase(job->id);
}

void LocalFiles::cancel_all() {
	for (auto &[id, job] : jobs_) {
		job->stream->reset(0);
	}
	jobs_.clear();
}

} // namespace spectre
