// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/file_transfers.hpp"

#include "gdp/clock.hpp"
#include "log.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <system_error>
#include <vector>

namespace spectre {

namespace {

// Read pieces, few enough syscalls and small against the window.
constexpr size_t kChunk = 256 * 1024;
// File bytes sent but not yet acknowledged, per upload. A fixed cap: the
// uplink carries little else but StatsReports, which a deep queue would
// delay (docs/design/file-transfer.md, Limitations).
constexpr uint64_t kInFlight = 4ull << 20;

// std::filesystem takes UTF-8 only through u8string, which is what every
// path here is (SDL hands them over in UTF-8, Windows included).
std::filesystem::path fs_path(const std::string &utf8) {
	return std::filesystem::path(std::u8string(utf8.begin(), utf8.end()));
}

std::string utf8_path(const std::filesystem::path &path) {
	std::u8string s = path.u8string();
	return std::string(s.begin(), s.end());
}

// The file's modification time in Unix milliseconds, 0 if unknown. Through
// both clocks' now(): file_clock's epoch is the library's to choose.
int64_t mtime_unix_ms(const std::filesystem::path &path) {
	std::error_code ec;
	auto written = std::filesystem::last_write_time(path, ec);
	if (ec) {
		return 0;
	}
	auto since = written - std::filesystem::file_time_type::clock::now();
	auto when = std::chrono::system_clock::now() + std::chrono::duration_cast<std::chrono::system_clock::duration>(since);
	return std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch()).count();
}

const char *file_error_text(gdp::session::FileErrorCode code) {
	switch (code) {
	case gdp::session::FILE_ERROR_UNSUPPORTED: return "the host doesn't take it";
	case gdp::session::FILE_ERROR_BAD_NAME: return "the host refused its name";
	case gdp::session::FILE_ERROR_NO_SPACE: return "not enough space on the host";
	case gdp::session::FILE_ERROR_REFUSED: return "the host refused it";
	case gdp::session::FILE_ERROR_WRITE_FAILED: return "the host couldn't store it";
	case gdp::session::FILE_ERROR_SIZE_MISMATCH: return "it changed size while it was sent";
	default: return "the host gave no reason";
	}
}

} // namespace

struct FileTransfers::Job {
	uint64_t id = 0;
	std::string name; // the file's name on the wire
	std::string path; // the local file
	std::unique_ptr<gdp::Stream> stream;
	// Waiting for the first FileReply until then; 0 once it came.
	uint64_t deadline_us = 0;
	uint64_t size = 0;
	std::ifstream in;
	gdp::FrameReader replies;
	uint64_t header = 0; // the StreamOpen frame, ahead of the file's bytes
	uint64_t sent = 0;   // file bytes handed to the stream
	uint64_t acked = 0;  // ... and acknowledged by the host
};

FileTransfers::FileTransfers(OpenStream open_stream) : open_stream_(std::move(open_stream)) {}

FileTransfers::~FileTransfers() {
	cancel_all();
}

bool FileTransfers::upload(const std::string &path, std::string *error) {
	std::filesystem::path p = fs_path(path);
	std::error_code ec;
	std::filesystem::file_status status = std::filesystem::status(p, ec);
	if (ec || !std::filesystem::is_regular_file(status)) {
		*error = std::filesystem::is_directory(status) ? "folders can't be sent" : "it isn't a file";
		return false;
	}
	std::string name = utf8_path(p.filename());
	// gdp-spec.md §7.12 also wants NFC, which a macOS name (NFD) isn't:
	// sent as it is, a host on a byte-for-byte file system takes it anyway.
	if (!gdp::valid_file_name(name)) {
		*error = "its name can't be sent";
		return false;
	}
	auto job = std::make_unique<Job>();
	job->id = next_id_++;
	job->name = std::move(name);
	job->path = path;
	queued_.push_back(std::move(job));
	start_more();
	return true;
}

void FileTransfers::tick(uint64_t now_us) {
	std::vector<Job *> late;
	for (const auto &[id, job] : active_) {
		if (job->deadline_us != 0 && now_us >= job->deadline_us) {
			late.push_back(job.get());
		}
	}
	for (Job *job : late) {
		fail(job, "the host didn't answer");
	}
}

void FileTransfers::cancel_all() {
	queued_.clear();
	for (auto &[id, job] : active_) {
		if (job->stream) {
			job->stream->reset(0);
		}
	}
	active_.clear();
}

void FileTransfers::start_more() {
	while (active_.size() < gdp::kFileStreamsAtOnce && !queued_.empty()) {
		std::unique_ptr<Job> owned = std::move(queued_.front());
		queued_.pop_front();
		Job *job = owned.get();
		active_[job->id] = std::move(owned);
		start(job);
	}
}

void FileTransfers::start(Job *job) {
	std::filesystem::path p = fs_path(job->path);
	std::error_code ec;
	job->size = std::filesystem::file_size(p, ec);
	if (!ec) {
		job->in.open(p, std::ios::binary);
	}
	if (ec || !job->in) {
		fail(job, "it can't be read");
		return;
	}
	job->stream = open_stream_();
	if (!job->stream) {
		fail(job, "the session doesn't take files");
		return;
	}
	job->stream->on_data = [this, job](const uint8_t *data, size_t len) { handle_data(job, data, len); };
	job->stream->on_fin = [this, job] { fail(job, "the host ended the transfer without saying why"); };
	job->stream->on_reset = [this, job](uint64_t) { fail(job, "the host cancelled it", false); };
	job->stream->on_acked = [this, job](uint64_t total) {
		job->acked = total > job->header ? total - job->header : 0;
		pump(job);
	};

	gdp::session::FileOpen open;
	open.mutable_offer()->set_name(job->name);
	open.mutable_offer()->set_size(job->size);
	open.mutable_offer()->set_modified_unix_ms(mtime_unix_ms(p));
	gdp::session::StreamOpen stream_open;
	stream_open.set_kind(gdp::kStreamKindFile);
	stream_open.set_params(open.SerializeAsString());
	std::vector<uint8_t> frame;
	gdp::encode_frame(stream_open, &frame);
	job->header = frame.size();
	job->stream->send(frame.data(), frame.size(), false);
	job->deadline_us = gdp::monotonic_us() + gdp::kFileReplyTimeoutMs * 1000ull;
	SLOG_INFO("files: offering \"%s\" (%llu bytes)", job->name.c_str(), (unsigned long long)job->size);
}

void FileTransfers::handle_data(Job *job, const uint8_t *data, size_t len) {
	job->stream->consume(len);
	job->replies.feed(data, len);
	gdp::session::FileReply reply;
	for (;;) {
		gdp::FrameReader::Result result = job->replies.drain(&reply);
		if (result == gdp::FrameReader::Result::kIncomplete) {
			return;
		}
		if (result != gdp::FrameReader::Result::kOk) {
			fail(job, "the host's reply didn't parse");
			return;
		}
		job->deadline_us = 0;
		switch (reply.reply_case()) {
		case gdp::session::FileReply::kAccepted:
			if (job->size == 0) {
				job->stream->send(nullptr, 0, true);
			}
			pump(job);
			return; // the job may be gone; nothing else comes before saved
		case gdp::session::FileReply::kSaved: succeed(job, reply.saved().directory()); return;
		case gdp::session::FileReply::kRefused:
			// gdp-spec.md §7.12: nothing more, and our direction ends with FIN.
			job->stream->send(nullptr, 0, true);
			fail(job, file_error_text(reply.refused().code()), false);
			return;
		case gdp::session::FileReply::kFailed: fail(job, file_error_text(reply.failed().code())); return;
		default: fail(job, "the host's reply made no sense"); return;
		}
	}
}

void FileTransfers::pump(Job *job) {
	while (job->sent < job->size && job->sent - std::min(job->acked, job->sent) < kInFlight) {
		size_t n = static_cast<size_t>(std::min<uint64_t>(kChunk, job->size - job->sent));
		std::vector<uint8_t> buf(n);
		job->in.read(reinterpret_cast<char *>(buf.data()), static_cast<std::streamsize>(n));
		if (static_cast<size_t>(job->in.gcount()) != n) {
			fail(job, "it changed while it was being sent");
			return;
		}
		job->sent += n;
		job->stream->send(buf.data(), n, job->sent == job->size);
	}
}

void FileTransfers::succeed(Job *job, const std::string &where) {
	auto it = active_.find(job->id);
	if (it == active_.end()) {
		return;
	}
	std::unique_ptr<Job> owned = std::move(it->second);
	active_.erase(it);
	std::string name = owned->name;
	// Our direction ended with FIN: the stream goes gracefully.
	owned.reset();
	SLOG_INFO("files: the host saved \"%s\" in %s", name.c_str(), where.c_str());
	if (on_uploaded) {
		on_uploaded(name, where);
	}
	start_more();
}

void FileTransfers::fail(Job *job, const std::string &why, bool reset) {
	auto it = active_.find(job->id);
	if (it == active_.end()) {
		return;
	}
	std::unique_ptr<Job> owned = std::move(it->second);
	active_.erase(it);
	if (owned->stream && reset) {
		owned->stream->reset(0); // gdp-spec.md §7.12: a cancel is a reset, code 0
	}
	std::string name = owned->name;
	owned.reset();
	SLOG_INFO("files: \"%s\" failed: %s", name.c_str(), why.c_str());
	if (on_failed) {
		on_failed(name, why);
	}
	start_more();
}

} // namespace spectre
