// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// This client's files for the host (gdp-spec.md §7.12): what its user
// copied (file-clipboard), and folders it shares (file-share), each answered
// when the host asks (FileFetch) on a "file" stream of this client's: a
// folder's contents, or a file's bytes from an offset. What a list or a
// share names is all the host can reach: a list by index, a share by a path
// that never leaves it (gdp::resolve_beneath()).
//
// Main thread, from SessionClient::dispatch(); files are read inline, a
// 256 KiB piece at a time, as fast as the host acknowledges them.
#pragma once

#include "gdp/file_list.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <cstdint>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace spectre {

class LocalFiles {
public:
	using OpenStream = std::function<std::unique_ptr<gdp::Stream>()>;
	// `now_us`: the clock lists age by (gdp::monotonic_us() unless a test
	// says otherwise).
	explicit LocalFiles(OpenStream open_stream, std::function<uint64_t()> now_us = {});
	~LocalFiles();
	LocalFiles(const LocalFiles &) = delete;
	LocalFiles &operator=(const LocalFiles &) = delete;

	// The local clipboard now holds the files at `paths` (none: it no longer
	// holds files): the FileList to send, with what is in the folders. The
	// list it replaces is still answered a while, as the host does.
	gdp::session::FileList set_list(const std::vector<std::string> &paths);
	// Whether the last list sent had files.
	bool has_list() const { return has_list_; }

	// Shares the folder at `path` (UTF-8): its id, or 0 if it isn't a
	// folder. `name` is what the host is told to call it: given, or empty
	// for the folder's own name, filled in. Unless `include_hidden`, hidden
	// files and folders in it (gdp::hidden_local()) are neither listed nor
	// read, whatever path the host asks for.
	uint64_t add_share(const std::string &path, bool include_hidden, std::string *name);
	// Stops answering for a share; what is being read from it goes on.
	void remove_share(uint64_t id) { shares_.erase(id); }

	// Answers `fetch` on a stream of its own.
	void answer(const gdp::session::FileFetch &fetch);
	// Resets every answer still going.
	void cancel_all();
	size_t active() const { return jobs_.size(); }

	// Same rule as the host's FileSender (gdp-spec.md §7.12): the latest and
	// up to this many earlier lists, each until this long after it was
	// replaced or last read from.
	static constexpr size_t kKeptLists = 4;
	static constexpr uint64_t kKeptListUs = 10ull * 60 * 1000000;

private:
	struct Job;
	struct List {
		gdp::LocalFileList files;
		uint64_t replaced_us = 0;
		uint64_t last_used_us = 0;
	};
	List *use_list(uint64_t list_id);
	void expire_lists(uint64_t now_us);
	void send_reply(gdp::Stream &stream, const gdp::session::FileReply &reply);
	void refuse(std::unique_ptr<gdp::Stream> stream, gdp::session::FileErrorCode code);
	void send_listing(std::unique_ptr<gdp::Stream> stream, const std::vector<gdp::session::FileListing> &frames);
	void send_file(std::unique_ptr<gdp::Stream> stream, const std::string &path, const std::string &name,
		const gdp::session::FileFetch &fetch);
	void pump(Job *job);
	void remove(Job *job);

	OpenStream open_stream_;
	std::function<uint64_t()> now_us_;
	uint64_t list_id_ = 0;
	bool has_list_ = false;
	std::map<uint64_t, List> lists_;
	struct Share {
		std::string folder;
		bool include_hidden = false;
	};
	std::map<uint64_t, Share> shares_;
	uint64_t next_share_ = 1;
	std::map<uint64_t, std::unique_ptr<Job>> jobs_;
	uint64_t next_job_ = 1;
};

} // namespace spectre
