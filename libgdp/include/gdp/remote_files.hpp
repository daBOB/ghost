// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// RemoteFiles: the other end's files in a RemoteMount (gdp-spec.md §7.12):
// each FileList it sends becomes a folder (clip/<list_id>/), each folder it
// shares one more (shares/<name>/), and reading them turns into requests
// whose answers -- FileReply frames, then raw bytes -- feed the mount. Both
// ends use it, and differ only in how a request reaches the other end,
// which the owner supplies (Requester):
//
// - the client opens a "file" stream with a FileRequest or
//   FileListingRequest for the host's lists, and hands it straight back;
// - the host sends a FileFetch on the control stream, and hands back the
//   client's answering stream when it comes (FileAnswer).
//
// Owner's thread only, from dispatch() and the owner's own stream
// callbacks, like RemoteMount. Inert where FUSE isn't built (supported()).
#pragma once

#include "gdp/remote_mount.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace gdp {

class RemoteFiles {
public:
	// What a request is for: an entry of one of the other end's lists, or
	// a path in one of its shared folders.
	struct Target {
		uint64_t list_id = 0;
		uint32_t index = 0;
		uint64_t share_id = 0; // nonzero: a shared folder's `path`
		std::string path;
	};

	// Asks the other end for `target`: its contents from `offset` (to the end
	// of the file), or with `listing` what is in the folder. Answer with
	// answer(id, ...) once there is a stream carrying the reply, or fail(id).
	using Requester = std::function<void(uint64_t id, const Target &target, uint64_t offset, bool listing)>;

	// The newest lists kept in the mount, the latest included: the other
	// end keeps answering earlier ones a while (gdp-spec.md §7.12).
	static constexpr size_t kKeptLists = 5;
	// How long a shared folder's listing (and what the kernel knows of its
	// entries) stays good.
	static constexpr double kShareRefreshSeconds = 5;

	explicit RemoteFiles(Requester requester);
	~RemoteFiles();
	RemoteFiles(const RemoteFiles &) = delete;
	RemoteFiles &operator=(const RemoteFiles &) = delete;

	static bool supported() { return RemoteMount::supported(); }

	// Mounts at `directory`. False, with why, if it can't.
	bool start(const std::string &directory, std::string *error);
	// Fails what is waiting, closes every stream and unmounts.
	void stop();
	bool running() const { return mount_.mounted(); }
	bool contains(const std::string &path) const { return mount_.contains(path); }
	const std::string &directory() const { return mount_.directory(); }

	int notify_fd() const { return mount_.notify_fd(); }
	void dispatch() { mount_.dispatch(); }
	// Fails requests the other end hasn't answered within
	// gdp::kFileReplyTimeoutMs. Call it from the owner's loop.
	void tick(uint64_t now_us);

	// A FileList from the other end: its own folder, clip/<list_id>/, with
	// everything the list describes (folders it leaves unlisted are asked for
	// when opened). Returns the local paths of what was copied, to offer on
	// the clipboard; empty for an empty list. Older lists past kKeptLists go.
	std::vector<std::string> add_list(const session::FileList &list);
	// A folder the other end shares, as shares/<name>/ (numbered if the name
	// is taken). Returns its local path.
	std::string add_share(uint64_t share_id, const std::string &name);
	void remove_share(uint64_t share_id);

	// The stream carrying the reply to request `id`, and what of it already
	// arrived with its opening frame (and was consumed: the host's
	// FileReceiver gives a stream's first bytes their credit back). A stream
	// for a request no longer wanted is reset.
	void answer(uint64_t id, std::unique_ptr<Stream> stream, std::vector<uint8_t> data = {});
	void fail(uint64_t id, int error);

	// For tests and logs.
	size_t pending_requests() const { return requests_.size(); }
	RemoteMount &mount() { return mount_; }

private:
	struct Request;
	uint64_t request(const Target &target, uint64_t offset, bool listing, uint64_t range, RemoteMount::Node folder);
	void handle_data(uint64_t id, const uint8_t *data, size_t len);
	void handle_fin(uint64_t id);
	void finish(uint64_t id, int error);
	// Gives `n` bytes of request `req`'s stream their credit back, less
	// what was given back already for bytes that came with its opening frame.
	void give_back(Request &req, size_t n);
	uint64_t key_for(const Target &target);
	RemoteMount::Entry entry_for(const session::FileListEntry &e, const Target &target, bool in_share);
	RemoteMount::Node folder(const char *name);

	Requester requester_;
	RemoteMount mount_;
	std::map<uint64_t, std::unique_ptr<Request>> requests_;
	std::map<uint64_t, uint64_t> by_range_; // mount range -> request
	uint64_t next_request_ = 1;
	std::map<uint64_t, Target> targets_; // mount entry key -> what it is
	uint64_t next_key_ = 1;
	struct KeptList {
		uint64_t list_id;
		RemoteMount::Node node;
		std::vector<uint64_t> keys;
	};
	std::vector<KeptList> lists_; // oldest first
	std::map<uint64_t, RemoteMount::Node> shares_;
};

} // namespace gdp
