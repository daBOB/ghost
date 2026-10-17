// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The client's files on the host (gdp-spec.md §7.12): what its user copied
// (file-clipboard), for a paste in the session, and the folders it shares
// (file-share), in the file manager's sidebar. Both live in one FUSE mount
// (gdp::RemoteFiles) under $XDG_RUNTIME_DIR/ghost/files, made when first
// needed and gone with the session; reading them asks the client with a
// FileFetch, and the client's answering stream comes back through
// FileReceiver::on_answer.
//
// Event loop only. The mount's own requests are served from the same loop,
// so nothing on it may touch the mount (contains() is how the clipboard's
// copied files keep clear of it).
#pragma once

#include "gdp/remote_files.hpp"
#include "session.pb.h"
#include "util/event_source.hpp"

#include <wayland-server-core.h>

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace wraith {

class ClientFiles {
public:
	// `send_fetch` puts a FileFetch on the control stream. `bookmarks`:
	// give shared folders sidebar entries (file_bookmarks.hpp).
	ClientFiles(struct wl_event_loop *loop, std::function<void(const gdp::session::FileFetch &)> send_fetch,
		bool bookmarks);
	~ClientFiles();
	ClientFiles(const ClientFiles &) = delete;
	ClientFiles &operator=(const ClientFiles &) = delete;

	// Where the mount goes; empty without FUSE or a runtime directory.
	static std::string mount_directory();
	// Whether the client's files can be mounted here at all (FUSE usable,
	// a runtime directory): what file-clipboard and file-share need.
	static bool can_mount();
	// Removes sidebar entries a wraith that died left behind. Called once at
	// startup.
	static void clean_up_after_crash();

	// The client's copied files, mounted: the paths to put on the session's
	// clipboard (empty for an empty list, or when nothing can be mounted).
	std::vector<std::string> add_list(const gdp::session::FileList &list);
	// A folder the client shares, or stops sharing.
	void share(const gdp::session::FileShare &share);
	// The client's answer to one of our FileFetches.
	void answer(std::unique_ptr<gdp::Stream> stream, const gdp::session::FileAnswer &answer,
		std::vector<uint8_t> data);

	bool contains(const std::string &path) const { return files_.contains(path); }
	bool running() const { return files_.running(); }
	// For tests and logs.
	const gdp::RemoteFiles &files() const { return files_; }

private:
	bool start();

	struct wl_event_loop *loop_;
	std::function<void(const gdp::session::FileFetch &)> send_fetch_;
	bool bookmarks_;
	bool failed_ = false;
	gdp::RemoteFiles files_;
	EventSource fd_source_;
	EventSource timer_;
	std::map<uint64_t, std::string> share_paths_;
};

} // namespace wraith
