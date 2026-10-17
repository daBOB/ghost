// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// File transfer, spectre's end (gdp-spec.md §7.12): files dropped on the
// window go to the host, one "file" stream each. At most
// gdp::kFileStreamsAtOnce are open at once; the rest wait their turn here.
//
// Everything runs on the main thread, from SessionClient::dispatch() and
// tick(): files are read inline, a 256 KiB piece at a time.
#pragma once

#include "gdp/framing.hpp"
#include "gdp/file_transfer.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <cstdint>
#include <deque>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>

namespace spectre {

class FileTransfers {
public:
	// Opens a "file" stream (SessionClient::open_file_stream()), or null
	// when the session can't take one.
	using OpenStream = std::function<std::unique_ptr<gdp::Stream>()>;
	explicit FileTransfers(OpenStream open_stream);
	~FileTransfers();
	FileTransfers(const FileTransfers &) = delete;
	FileTransfers &operator=(const FileTransfers &) = delete;

	// Queues the local file at `path` (UTF-8) to send to the host. False,
	// with why in `error`, if it can't be offered at all: not a regular
	// file (a folder), or a name the host would refuse.
	bool upload(const std::string &path, std::string *error);

	// Gives up on an offer the host hasn't answered within
	// gdp::kFileReplyTimeoutMs. Call it from the main loop.
	void tick(uint64_t now_us);
	// Resets every stream and forgets everything queued.
	void cancel_all();
	// Uploads open or queued.
	size_t pending() const { return active_.size() + queued_.size(); }

	// One per file, from dispatch() or tick(). Destroying this object from
	// inside them is not supported.
	// The host stored it as `name` in its folder `where` (may be empty).
	std::function<void(const std::string &name, const std::string &where)> on_uploaded;
	std::function<void(const std::string &name, const std::string &why)> on_failed;

private:
	struct Job;
	void start_more();
	void start(Job *job);
	void handle_data(Job *job, const uint8_t *data, size_t len);
	void pump(Job *job);
	// Ends `job`: reports it, drops its stream (reset unless our side
	// already finished) and starts what is queued.
	void succeed(Job *job, const std::string &where);
	void fail(Job *job, const std::string &why, bool reset = true);

	OpenStream open_stream_;
	uint64_t next_id_ = 1;
	std::map<uint64_t, std::unique_ptr<Job>> active_;
	std::deque<std::unique_ptr<Job>> queued_;
};

} // namespace spectre
