// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The host's end of copied files going to the client (gdp-spec.md §7.12):
// the FileList of what the user copied (with file-clipboard, what is in its
// folders too, and listings of the rest on request), and each file (or
// range of one) the viewer asks for by its index in a list still kept: the
// latest, and up to kKeptLists earlier ones until kKeptListUs after each was
// replaced or last read from, so a paste still reading survives a new copy.
//
// Files are read by a thread of its own, like FileReceiver's writes, and
// folders by another (building a list, listing a folder), so a slow disk
// never stalls the event loop that encodes the desktop. File
// data shares the downlink with the video, so what is in flight follows
// the connection's round-trip time (FileWindow: grow while the queueing
// delay stays small, halve when it builds), and nothing more goes out
// while the video's own send queue has a backlog.
#pragma once

#include "gdp/file_list.hpp"
#include "gdp/transport.hpp"
#include "gdp/worker.hpp"
#include "session.pb.h"
#include "util/event_source.hpp"

#include <wayland-server-core.h>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wraith {

// How many file bytes may be in flight to the client: LEDBAT-style, the
// same rule as the client's uploads (SpectreKit's UploadWindow).
class FileWindow {
public:
	static constexpr uint64_t kMinimum = 256 * 1024;
	static constexpr uint64_t kMaximum = 16 << 20;
	static constexpr uint64_t kInitial = 2 << 20;
	static constexpr uint32_t kTargetDelayUs = 25000;
	static constexpr uint64_t kStep = 256 * 1024;

	uint64_t bytes() const { return bytes_; }
	uint32_t base_rtt_us() const { return base_rtt_us_; }
	// One sample of the connection's smoothed RTT at `now_us`.
	void update(uint32_t rtt_us, uint64_t now_us);

private:
	uint64_t bytes_ = kInitial;
	uint32_t base_rtt_us_ = 0;
	uint64_t last_decrease_us_ = 0;
	bool decreased_ = false;
};

class FileSender {
public:
	// Earlier lists still answered, and for how long after each was
	// replaced or last read from, whichever is later.
	static constexpr size_t kKeptLists = 4;
	static constexpr uint64_t kKeptListUs = 10ull * 60 * 1000000;

	// `rtt_us`: the connection's RTT now. `video_queue_clear`: false while
	// the video's send queue has a backlog (GdpSession::send_queue_clear()).
	// `now_us`: the clock lists age by (gdp::monotonic_us() unless a test
	// says otherwise).
	FileSender(struct wl_event_loop *loop, std::function<uint32_t()> rtt_us,
		std::function<bool()> video_queue_clear, std::function<uint64_t()> now_us = {});
	~FileSender();

	FileSender(const FileSender &) = delete;
	FileSender &operator=(const FileSender &) = delete;

	// The clipboard now holds `paths` (none: it no longer holds files). The
	// list is built off the event loop and handed to `ready`, to send, with
	// folder contents when `tree` (file-clipboard); not at all if set_list()
	// is called again first, since only the latest copy counts. The list it
	// replaces is kept a while (kKeptLists, kKeptListUs).
	using ListReady = std::function<void(const gdp::session::FileList &)>;
	void set_list(const std::vector<std::string> &paths, bool tree, ListReady ready);

	// A "file" stream whose FileOpen is `request` (FileReceiver hands
	// them over): answers it, and sends the file if it can.
	void serve(std::unique_ptr<gdp::Stream> stream, const gdp::session::FileRequest &request);
	// The same for a FileListingRequest (file-clipboard): the folder's
	// contents, in as many FileListing frames as they take, then FIN. A
	// folder not listed yet is read off the event loop first.
	void serve_listing(std::unique_ptr<gdp::Stream> stream, const gdp::session::FileListingRequest &request);

	size_t active_transfers() const { return transfers_.size(); }
	const FileWindow &window() const { return window_; }

private:
	struct OpenFile {
		int fd = -1;
		~OpenFile();
	};

	struct Transfer {
		uint64_t id = 0;
		std::unique_ptr<gdp::Stream> stream;
		std::shared_ptr<OpenFile> file;
		std::string name;
		uint64_t start = 0;   // the file offset the range begins at
		uint64_t size = 0;    // bytes of the file to send, from `start`
		uint64_t header = 0;  // bytes of the FileReply frame ahead of the file
		uint64_t asked = 0;   // offset the reader has been asked up to
		uint64_t sent = 0;    // file bytes handed to the stream
		uint64_t acked = 0;   // file bytes the client acknowledged
		bool reading = false; // a read is out
	};

	struct ReadJob {
		uint64_t transfer = 0;
		std::shared_ptr<OpenFile> file;
		uint64_t offset = 0;
		size_t len = 0;
	};
	struct ReadDone {
		uint64_t transfer = 0;
		std::vector<uint8_t> data;
		bool short_read = false; // the file ended (or failed) early
	};

	void refuse(std::unique_ptr<gdp::Stream> stream, gdp::session::FileErrorCode code);
	void acknowledged(Transfer *t, uint64_t total);
	// Asks the reader for more of each transfer, as far as the window and
	// the video allow.
	void pump();
	void drain_reads();
	void remove(Transfer *t);
	uint64_t in_flight() const;
	void reader_main();
	// Forgets the earlier lists past kKeptLists or kKeptListUs.
	void expire_lists(uint64_t now_us);
	struct List;
	// A list still kept, marked as read from now; null if gone.
	List *use_list(uint64_t list_id);
	// Folder `index` of `list`, listed already: its FileListing frames, FIN.
	void send_listing(gdp::Stream &stream, gdp::LocalFileList &list, uint32_t index);

	struct wl_event_loop *loop_;
	std::function<uint32_t()> rtt_us_;
	std::function<bool()> video_queue_clear_;

	// A list the client may still fetch from.
	struct List {
		gdp::LocalFileList files;
		uint64_t replaced_us = 0;  // 0 while it is the latest
		uint64_t last_used_us = 0; // the last request against it
	};
	std::function<uint64_t()> now_us_;
	uint64_t list_id_ = 0;        // the latest
	uint64_t requested_list_ = 0; // the latest asked for: list_id_ once built
	std::map<uint64_t, List> lists_;
	// Reads folders; before its source, which goes first.
	gdp::Worker folders_;
	EventSource folders_source_;

	std::map<uint64_t, std::unique_ptr<Transfer>> transfers_;
	uint64_t next_transfer_ = 1;
	FileWindow window_;
	uint64_t last_sample_us_ = 0;
	// Retries pump() while the video's backlog holds file data back.
	EventSource retry_timer_;

	std::thread reader_;
	std::mutex mutex_;
	std::condition_variable wake_;
	std::deque<ReadJob> jobs_;
	std::vector<ReadDone> done_;
	bool stopping_ = false;
	int done_fd_ = -1;
	EventSource done_source_;
};

} // namespace wraith
