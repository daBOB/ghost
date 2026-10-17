// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// RemoteMount: a read-only FUSE mount of the other end's files (gdp-spec.md
// §7.12): what its user copied, or a folder it shares. A paste puts paths
// into it on the local clipboard, and the file manager copies from it as
// from any folder, while the bytes come over the network as they are read.
// Linux only: built when libfuse3 is (GDP_HAVE_FUSE).
//
// Threads: FUSE's own loop runs on a thread of this object's and only hands
// each request over; everything else -- the tree, the callbacks, the
// answers -- runs on the owner's thread, from dispatch(), like
// gdp::Connection's. The owner must never touch the mount itself from that
// thread (a stat of a path in it would wait for a dispatch() that can't
// come): paths a local copy put on the clipboard that lead into the mount
// are the owner's to recognise and leave alone (contains()).
//
// Reading: each open file has one range at a time, from where its reads
// are to the end of the file, which the owner streams in (range_data()) and
// this hands to FUSE as the reads come; a read outside what the range has
// brought or will bring closes it and opens another where the read is. So
// a file copied from start to end costs one request, however it's read.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace gdp {

class RemoteMount {
public:
	using Node = uint64_t;
	static constexpr Node kRoot = 1;

	struct Entry {
		std::string name; // gdp::valid_file_name()
		bool directory = false;
		uint64_t size = 0;
		int64_t modified_unix_ms = 0;
		// A folder whose contents are known; else on_list asks for them the
		// first time they're wanted.
		bool listed = true;
		// A folder's contents are asked for again when they are older than
		// this, the next time they're wanted (0: never; a shared folder
		// changes, a copy doesn't). Also how long the kernel may keep what it
		// was told about the entry.
		double refresh_seconds = 0;
		// The owner's own handle for the entry, handed back in callbacks.
		uint64_t key = 0;
	};

	RemoteMount();
	~RemoteMount();
	RemoteMount(const RemoteMount &) = delete;
	RemoteMount &operator=(const RemoteMount &) = delete;

	// Whether this build has FUSE at all.
	static bool supported();
	// Whether a mount can be made here: FUSE built in, /dev/fuse open to us,
	// and fusermount3 installed (it does the mounting for a user). What a
	// side checks before offering what needs a mount.
	static bool available();

	// Mounts an empty folder at `directory` (created if missing; must be
	// empty), read-only, unmounted again if this process dies. False, with
	// why in `error`, if it can't be.
	bool mount(const std::string &directory, std::string *error);
	// Fails every request still waiting, unmounts and stops FUSE's thread.
	void unmount();
	bool mounted() const;
	const std::string &directory() const { return directory_; }
	// Whether `path` is the mount or inside it.
	bool contains(const std::string &path) const;

	// Readable whenever dispatch() has work.
	int notify_fd() const;
	void dispatch();

	// The tree. `parent` is kRoot or a folder added before.
	Node add(Node parent, const Entry &entry);
	// Removes `node` and everything under it. Open files read past what they
	// have get EIO.
	void remove(Node node);
	// The answer to on_list: `folder`'s contents, matched by name to what
	// it had (an entry still there keeps its node).
	void set_children(Node folder, const std::vector<Entry> &children);
	void fail_children(Node folder, int error);
	// The local path of `node` ("" if gone).
	std::string path_of(Node node) const;
	// `parent`'s child called `name`, or 0.
	Node child(Node parent, const std::string &name) const;

	// What the owner provides, all called from dispatch():
	// `folder`'s contents are wanted: answer with set_children() or
	// fail_children(), now or later.
	std::function<void(Node folder, uint64_t key)> on_list;
	// Stream file `key` from `offset` to its end into range_data(range, ...),
	// then range_end(range, 0); or range_end(range, errno) if it can't.
	std::function<void(uint64_t range, Node file, uint64_t key, uint64_t offset)> on_open_range;
	// Stop range `range`: nothing more of it is wanted.
	std::function<void(uint64_t range)> on_close_range;
	// `bytes` more of range `range` have gone to FUSE: what flow control
	// gives back (gdp::Stream::consume()).
	std::function<void(uint64_t range, size_t bytes)> on_consumed;

	void range_data(uint64_t range, const uint8_t *data, size_t len);
	void range_end(uint64_t range, int error);

	// For tests and logs: ranges opened so far.
	uint64_t ranges_opened() const;

	struct Impl;

private:
	std::unique_ptr<Impl> impl_;
	std::string directory_;
};

// Whether `path` is one of this process's mounts or inside one, by its
// name alone: nothing is looked up, so it can't wait on the mount. What
// reads local folders (gdp/file_list.hpp) leaves these out, since the
// thread serving a mount is the one that would be reading it. Any thread.
bool inside_own_mount(const std::string &path);

} // namespace gdp
