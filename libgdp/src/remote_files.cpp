// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/remote_files.hpp"

#include "gdp/clock.hpp"
#include "gdp/file_transfer.hpp"
#include "gdp/framing.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>

namespace gdp {

namespace {

// What a folder the mount makes up itself (clip, shares, a list's) shows
// as its modification time: when it was made, rather than 1970.
int64_t now_unix_ms() {
	return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
		.count();
}

int errno_for(session::FileErrorCode code) {
	switch (code) {
	case session::FILE_ERROR_GONE: return ENOENT;
	case session::FILE_ERROR_REFUSED: return EACCES;
	default: return EIO;
	}
}

} // namespace

struct RemoteFiles::Request {
	bool listing = false;
	uint64_t range = 0;             // a file's bytes: the mount's range
	RemoteMount::Node folder = 0;   // a listing: the folder it is for
	Target target;
	uint64_t offset = 0;
	uint64_t deadline_us = 0;       // waiting for the reply until then; 0 once it came
	std::unique_ptr<Stream> stream;
	size_t consumed_early = 0;      // credit given back for bytes not yet passed on
	// A file's bytes: one FileReply, then raw bytes.
	FrameThenRawReader reader{kMaxFileOpenFrameSize};
	uint64_t fed = 0;
	bool replied = false;
	uint64_t skip = 0;              // bytes before `offset` a host that ignores ranges sends
	uint64_t size = 0;
	uint64_t received = 0;
	// A listing: FileReply frames until FIN.
	FrameReader frames;
	std::vector<RemoteMount::Entry> entries;
};

RemoteFiles::RemoteFiles(Requester requester) : requester_(std::move(requester)) {
	mount_.on_open_range = [this](uint64_t range, RemoteMount::Node, uint64_t key, uint64_t offset) {
		auto it = targets_.find(key);
		if (it == targets_.end()) {
			mount_.range_end(range, ENOENT);
			return;
		}
		by_range_[range] = request(it->second, offset, false, range, 0);
	};
	mount_.on_close_range = [this](uint64_t range) {
		auto it = by_range_.find(range);
		if (it == by_range_.end()) {
			return;
		}
		auto req = requests_.find(it->second);
		if (req != requests_.end()) {
			if (req->second->stream) {
				req->second->stream->reset(0); // gdp-spec.md §7.12: a cancel
			}
			requests_.erase(req);
		}
		by_range_.erase(it);
	};
	mount_.on_consumed = [this](uint64_t range, size_t bytes) {
		auto it = by_range_.find(range);
		if (it == by_range_.end()) {
			return;
		}
		auto req = requests_.find(it->second);
		if (req != requests_.end()) {
			give_back(*req->second, bytes);
		}
	};
	mount_.on_list = [this](RemoteMount::Node folder, uint64_t key) {
		auto it = targets_.find(key);
		if (it == targets_.end()) {
			mount_.fail_children(folder, ENOENT);
			return;
		}
		request(it->second, 0, true, 0, folder);
	};
}

RemoteFiles::~RemoteFiles() {
	stop();
}

bool RemoteFiles::start(const std::string &directory, std::string *error) {
	return mount_.mount(directory, error);
}

void RemoteFiles::stop() {
	for (auto &[id, req] : requests_) {
		if (req->stream) {
			req->stream->reset(0);
		}
	}
	requests_.clear();
	by_range_.clear();
	mount_.unmount();
	targets_.clear();
	lists_.clear();
	shares_.clear();
}

uint64_t RemoteFiles::request(const Target &target, uint64_t offset, bool listing, uint64_t range,
	RemoteMount::Node folder) {
	uint64_t id = next_request_++;
	auto req = std::make_unique<Request>();
	req->listing = listing;
	req->range = range;
	req->folder = folder;
	req->target = target;
	req->offset = offset;
	req->deadline_us = monotonic_us() + kFileReplyTimeoutMs * 1000ull;
	requests_[id] = std::move(req);
	requester_(id, target, offset, listing);
	return id;
}

void RemoteFiles::tick(uint64_t now_us) {
	std::vector<uint64_t> late;
	for (const auto &[id, req] : requests_) {
		if (req->deadline_us != 0 && now_us >= req->deadline_us) {
			late.push_back(id);
		}
	}
	for (uint64_t id : late) {
		fail(id, EIO);
	}
}

void RemoteFiles::answer(uint64_t id, std::unique_ptr<Stream> stream, std::vector<uint8_t> data) {
	auto it = requests_.find(id);
	if (it == requests_.end() || it->second->stream) {
		stream->reset(0); // given up on, or answered twice
		return;
	}
	Request &req = *it->second;
	req.stream = std::move(stream);
	req.consumed_early = data.size();
	req.stream->on_data = [this, id](const uint8_t *d, size_t len) { handle_data(id, d, len); };
	req.stream->on_fin = [this, id] { handle_fin(id); };
	req.stream->on_reset = [this, id](uint64_t) { finish(id, EIO); };
	if (!data.empty()) {
		handle_data(id, data.data(), data.size());
	}
}

void RemoteFiles::fail(uint64_t id, int error) {
	finish(id, error);
}

void RemoteFiles::give_back(Request &req, size_t n) {
	size_t early = std::min(n, req.consumed_early);
	req.consumed_early -= early;
	if (n > early && req.stream) {
		req.stream->consume(n - early);
	}
}

void RemoteFiles::handle_data(uint64_t id, const uint8_t *data, size_t len) {
	auto it = requests_.find(id);
	if (it == requests_.end()) {
		return;
	}
	Request &req = *it->second;
	if (req.listing) {
		give_back(req, len);
		session::FileReply reply;
		int error = 0;
		bool ok = req.frames.feed_and_drain(data, len, &reply, [&] {
			req.deadline_us = 0;
			if (reply.has_refused()) {
				error = errno_for(reply.refused().code());
				return false;
			}
			if (!reply.has_listing()) {
				error = EIO;
				return false;
			}
			const session::FileListing &l = reply.listing();
			for (int i = 0; i < l.files_size(); i++) {
				const session::FileListEntry &e = l.files(i);
				if (!valid_file_name(e.name())) {
					continue;
				}
				Target t;
				if (req.target.share_id) {
					t.share_id = req.target.share_id;
					t.path = req.target.path.empty() ? e.name() : req.target.path + "/" + e.name();
				} else {
					t.list_id = req.target.list_id;
					t.index = l.first_index() + static_cast<uint32_t>(i);
				}
				req.entries.push_back(entry_for(e, t, req.target.share_id != 0));
			}
			return true;
		});
		if (!ok || error) {
			finish(id, error ? error : EIO);
		}
		return;
	}

	req.fed += len;
	FrameThenRawReader::State state = req.reader.feed(data, len);
	if (state == FrameThenRawReader::State::kError) {
		finish(id, EIO);
		return;
	}
	if (state != FrameThenRawReader::State::kFramed) {
		return;
	}
	std::vector<uint8_t> raw = req.reader.take_data();
	if (!req.replied) {
		req.replied = true;
		req.deadline_us = 0;
		give_back(req, static_cast<size_t>(req.fed - raw.size())); // the reply frame
		session::FileReply reply;
		if (!reply.ParseFromString(req.reader.frame())) {
			finish(id, EIO);
			return;
		}
		if (reply.has_refused()) {
			finish(id, errno_for(reply.refused().code()));
			return;
		}
		if (!reply.has_sending() || reply.sending().offset() > req.offset) {
			finish(id, EIO);
			return;
		}
		// A host from before ranges sends the whole file from 0 (§7.12).
		req.skip = req.offset - reply.sending().offset();
		if (req.skip > reply.sending().size()) {
			finish(id, EIO);
			return;
		}
		req.size = reply.sending().size() - req.skip;
	}
	size_t at = 0;
	if (req.skip > 0) {
		size_t n = static_cast<size_t>(std::min<uint64_t>(req.skip, raw.size()));
		req.skip -= n;
		at = n;
		give_back(req, n);
	}
	size_t n = raw.size() - at;
	if (n == 0) {
		return;
	}
	if (req.received + n > req.size) {
		finish(id, EIO); // more than it said
		return;
	}
	req.received += n;
	mount_.range_data(req.range, raw.data() + at, n);
}

void RemoteFiles::handle_fin(uint64_t id) {
	auto it = requests_.find(id);
	if (it == requests_.end()) {
		return;
	}
	Request &req = *it->second;
	if (req.listing) {
		finish(id, req.deadline_us == 0 ? 0 : EIO);
	} else {
		finish(id, req.replied && req.skip == 0 && req.received == req.size ? 0 : EIO);
	}
}

void RemoteFiles::finish(uint64_t id, int error) {
	auto it = requests_.find(id);
	if (it == requests_.end()) {
		return;
	}
	std::unique_ptr<Request> req = std::move(it->second);
	requests_.erase(it);
	if (req->listing) {
		if (error) {
			mount_.fail_children(req->folder, error);
		} else {
			mount_.set_children(req->folder, req->entries);
		}
	} else {
		by_range_.erase(req->range);
		mount_.range_end(req->range, error);
	}
	// The stream goes with the request: gracefully once the other end
	// finished, else reset.
}

uint64_t RemoteFiles::key_for(const Target &target) {
	uint64_t key = next_key_++;
	targets_[key] = target;
	return key;
}

RemoteMount::Entry RemoteFiles::entry_for(const session::FileListEntry &e, const Target &target, bool in_share) {
	RemoteMount::Entry entry;
	entry.name = e.name();
	entry.directory = e.directory();
	entry.size = e.directory() ? 0 : e.size();
	entry.modified_unix_ms = e.modified_unix_ms();
	// A shared folder's are listed when opened, and again when stale.
	entry.listed = !e.directory() || (!in_share && !e.unlisted());
	entry.refresh_seconds = in_share ? kShareRefreshSeconds : 0;
	entry.key = key_for(target);
	return entry;
}

RemoteMount::Node RemoteFiles::folder(const char *name) {
	RemoteMount::Node node = mount_.child(RemoteMount::kRoot, name);
	if (node) {
		return node;
	}
	RemoteMount::Entry e;
	e.name = name;
	e.directory = true;
	e.modified_unix_ms = now_unix_ms();
	return mount_.add(RemoteMount::kRoot, e);
}

std::vector<std::string> RemoteFiles::add_list(const session::FileList &list, bool tree) {
	std::vector<std::string> copied;
	if (!running() || list.files_size() == 0) {
		return copied;
	}
	RemoteMount::Node clip = folder("clip");
	RemoteMount::Entry e;
	e.name = std::to_string(list.list_id());
	e.directory = true;
	e.modified_unix_ms = now_unix_ms();
	if (mount_.child(clip, e.name)) {
		return copied; // the same list again
	}
	KeptList kept{list.list_id(), mount_.add(clip, e), {}};
	// Entries come parents first (§7.12), so a parent's node is always made
	// before its children's.
	std::vector<RemoteMount::Node> nodes(static_cast<size_t>(list.files_size()), 0);
	for (int i = 0; i < list.files_size(); i++) {
		const session::FileListEntry &f = list.files(i);
		uint32_t parent = f.parent();
		RemoteMount::Node under = parent == 0 ? kept.node
			: parent <= static_cast<uint32_t>(i) ? nodes[parent - 1] : 0;
		if (!under || !valid_file_name(f.name()) || mount_.child(under, f.name())) {
			continue; // a parent out of order, a bad name, or a name taken twice
		}
		if (f.directory() && !tree) {
			continue; // a host from before file-clipboard: its folders can't be had
		}
		Target t;
		t.list_id = list.list_id();
		t.index = static_cast<uint32_t>(i);
		RemoteMount::Entry entry = entry_for(f, t, false);
		kept.keys.push_back(entry.key);
		nodes[i] = mount_.add(under, entry);
		if (parent == 0 && nodes[i]) {
			copied.push_back(mount_.path_of(nodes[i]));
		}
	}
	lists_.push_back(std::move(kept));
	while (lists_.size() > kKeptLists) {
		mount_.remove(lists_.front().node);
		for (uint64_t key : lists_.front().keys) {
			targets_.erase(key);
		}
		lists_.erase(lists_.begin());
	}
	return copied;
}

std::string RemoteFiles::add_share(uint64_t share_id, const std::string &name) {
	if (!running() || shares_.count(share_id) || !valid_file_name(name)) {
		return "";
	}
	RemoteMount::Node root = folder("shares");
	std::string shown = name;
	for (unsigned n = 2; mount_.child(root, shown); n++) {
		shown = name + " (" + std::to_string(n) + ")";
	}
	session::FileListEntry e;
	e.set_name(shown);
	e.set_directory(true);
	e.set_modified_unix_ms(now_unix_ms());
	Target t;
	t.share_id = share_id;
	RemoteMount::Node node = mount_.add(root, entry_for(e, t, true));
	shares_[share_id] = node;
	return mount_.path_of(node);
}

void RemoteFiles::remove_share(uint64_t share_id) {
	auto it = shares_.find(share_id);
	if (it == shares_.end()) {
		return;
	}
	mount_.remove(it->second);
	shares_.erase(it);
}

} // namespace gdp
