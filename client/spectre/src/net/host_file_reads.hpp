// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// HostFileReads: the host's copied files (gdp-spec.md §7.12), read from a
// thread other than the session's. Any thread posts a request -- a file's
// bytes from an offset, or what is in a folder -- and waits on the Read it
// gets back. The main thread, the only one that touches the connection,
// asks the host for each in dispatch() (Requester: a "file" stream with a
// FileRequest or FileListingRequest, as RemoteFiles' requests are) and
// moves the reply across.
//
// What it is for: pasting the host's files into Windows Explorer
// (host_files_clipboard_win.*), whose reads come in on a thread of their
// own and wait on the network, which the main thread never may. Nothing
// here is Windows': macOS' file promises could read through it too.
//
// A file's bytes get their stream's credit back (gdp::Stream::consume())
// only once the reading thread has taken them, so a slow paste target
// holds the host back rather than filling memory: what is buffered is at
// most the stream's window.
//
// The main thread wakes for nothing here: dispatch() is called on every
// pass of its loop, which on Windows runs every few milliseconds anyway.
#pragma once

#include "gdp/file_transfer.hpp"
#include "gdp/framing.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

namespace spectre {

class HostFileReads {
public:
	// An entry of one of the host's lists.
	struct Target {
		uint64_t list_id = 0;
		uint32_t index = 0;
	};

	// What a reply arrives on: a stream (answer()), or a test's stand-in.
	// Main thread only. Destroying it lets the stream go (gdp::Stream's
	// destructor: gracefully once both ends finished, else reset).
	class Channel {
	public:
		virtual ~Channel() = default;
		// Gives `n` received bytes their credit back.
		virtual void consume(size_t n) = 0;
		// The reply is no longer wanted: a cancel (gdp-spec.md §7.12).
		virtual void cancel() = 0;
	};

	struct Shared;

	// One request, for the thread that posted it. Destroying it cancels the
	// request. One thread at a time.
	class Read {
	public:
		explicit Read(std::shared_ptr<Shared> shared) : shared_(std::move(shared)) {}
		~Read();
		Read(const Read &) = delete;
		Read &operator=(const Read &) = delete;

		// A file's next bytes, up to `n`, waiting up to `timeout_ms` for
		// some: how many came (> 0), 0 at the end of the file, -1 if the
		// request failed or nothing came in time.
		int64_t read(uint8_t *buf, size_t n, uint32_t timeout_ms);
		// A folder's listing, waiting up to `timeout_ms` for all of it.
		// False if the request failed or didn't finish in time.
		bool listing(std::vector<gdp::session::FileListing> *frames, uint32_t timeout_ms);

	private:
		std::shared_ptr<Shared> shared_;
	};

	// Asks the host for `target`: its bytes from `offset`, or with `listing`
	// what is in the folder. Answer with answer(id, ...) once there is a
	// stream carrying the reply, or fail(id).
	using Requester = std::function<void(uint64_t id, const Target &target, uint64_t offset, bool listing)>;

	// `now_us`: the clock timeouts go by (gdp::monotonic_us() unless a test
	// says otherwise).
	explicit HostFileReads(Requester requester, std::function<uint64_t()> now_us = {});
	~HostFileReads();
	HostFileReads(const HostFileReads &) = delete;
	HostFileReads &operator=(const HostFileReads &) = delete;

	// Any thread. After close(), what is posted fails at once.
	std::unique_ptr<Read> post(const Target &target, uint64_t offset);
	std::unique_ptr<Read> post_listing(const Target &target);

	// Main thread, every loop pass: asks the host for what was posted, lets
	// go what was cancelled, and gives back the credit of what was taken.
	void dispatch();
	// Fails requests the host hasn't answered within gdp::kFileReplyTimeoutMs,
	// and those whose reader has waited that long for a byte that hasn't come.
	void tick(uint64_t now_us);
	// Fails everything, now and from here on: the connection is gone. A
	// reader waiting returns at once.
	void close();

	// The stream carrying the reply to request `id`; reset if the request
	// is no longer wanted.
	void answer(uint64_t id, std::unique_ptr<gdp::Stream> stream);
	void answer(uint64_t id, std::unique_ptr<Channel> channel);
	void fail(uint64_t id);
	// What request `id`'s channel delivered: its bytes, its FIN, its reset.
	// answer(id, stream) wires these to the stream itself.
	void data(uint64_t id, const uint8_t *bytes, size_t len);
	void fin(uint64_t id);
	void reset(uint64_t id);

	// For tests and logs: requests asked for and not yet finished.
	size_t active() const { return requests_.size(); }

private:
	struct Request;
	void finish(uint64_t id, bool ok);

	Requester requester_;
	std::function<uint64_t()> now_us_;
	// Any thread's: what was posted and not yet asked for, and whether the
	// connection is gone.
	std::mutex posted_mutex_;
	std::vector<std::shared_ptr<Shared>> posted_;
	bool closed_ = false;
	// Main thread's.
	std::map<uint64_t, std::unique_ptr<Request>> requests_;
	uint64_t next_id_ = 1;
};

// What a Read and the main thread share, under `mutex`.
struct HostFileReads::Shared {
	Target target;
	uint64_t offset = 0;
	bool is_listing = false;

	std::mutex mutex;
	std::condition_variable changed;
	// The main thread's: bytes not yet taken (from `head` on), a listing's
	// frames, and how it ended.
	std::vector<uint8_t> bytes;
	size_t head = 0;
	std::vector<gdp::session::FileListing> frames;
	bool ended = false;
	bool failed = false;
	// The reader's: it let go, and how many bytes it took since the main
	// thread last gave their credit back.
	bool cancelled = false;
	size_t taken = 0;
};

} // namespace spectre
