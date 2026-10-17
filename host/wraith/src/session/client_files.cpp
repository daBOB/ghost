// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "session/client_files.hpp"

#include "gdp/clock.hpp"
#include "session/file_bookmarks.hpp"
#include "util/log.hpp"

#include <cstdlib>

namespace wraith {

namespace {

// How often requests the client never answered are given up on.
constexpr int kTickMs = 1000;

} // namespace

ClientFiles::ClientFiles(struct wl_event_loop *loop, std::function<void(const gdp::session::FileFetch &)> send_fetch,
	bool bookmarks)
	: loop_(loop), send_fetch_(std::move(send_fetch)), bookmarks_(bookmarks),
	  files_([this](uint64_t id, const gdp::RemoteFiles::Target &target, uint64_t offset, bool listing) {
		  gdp::session::FileFetch fetch;
		  fetch.set_fetch_id(id);
		  if (target.share_id) {
			  fetch.set_share_id(target.share_id);
			  fetch.set_path(target.path);
		  } else {
			  fetch.set_list_id(target.list_id);
			  fetch.set_index(target.index);
		  }
		  fetch.set_offset(offset);
		  fetch.set_listing(listing);
		  send_fetch_(fetch);
	  }) {}

ClientFiles::~ClientFiles() {
	fd_source_.reset();
	timer_.reset();
	if (bookmarks_) {
		for (const auto &[id, path] : share_paths_) {
			remove_file_bookmarks(path);
		}
	}
	files_.stop();
}

std::string ClientFiles::mount_directory() {
	const char *runtime = getenv("XDG_RUNTIME_DIR");
	if (!gdp::RemoteFiles::supported() || !runtime || !*runtime) {
		return "";
	}
	return std::string(runtime) + "/ghost/files";
}

bool ClientFiles::can_mount() {
	return gdp::RemoteFiles::available() && !mount_directory().empty();
}

void ClientFiles::clean_up_after_crash() {
	std::string dir = mount_directory();
	if (!dir.empty()) {
		remove_file_bookmarks(dir);
	}
}

bool ClientFiles::start() {
	if (files_.running()) {
		return true;
	}
	if (failed_) {
		return false;
	}
	std::string dir = mount_directory();
	std::string error = "no FUSE in this build, or no XDG_RUNTIME_DIR";
	if (dir.empty() || !files_.start(dir, &error)) {
		// Once: the client's copies and shares then just don't show up here.
		WLOG_ERROR("files: can't mount the client's files: %s", error.c_str());
		failed_ = true;
		return false;
	}
	fd_source_.reset(wl_event_loop_add_fd(
		loop_, files_.notify_fd(), WL_EVENT_READABLE,
		[](int, uint32_t, void *data) {
			static_cast<ClientFiles *>(data)->files_.dispatch();
			return 0;
		},
		this));
	timer_.reset(wl_event_loop_add_timer(
		loop_,
		[](void *data) {
			auto *self = static_cast<ClientFiles *>(data);
			self->files_.tick(gdp::monotonic_us());
			wl_event_source_timer_update(self->timer_.get(), kTickMs);
			return 0;
		},
		this));
	wl_event_source_timer_update(timer_.get(), kTickMs);
	WLOG_INFO("files: the client's files are mounted at %s", dir.c_str());
	return true;
}

std::vector<std::string> ClientFiles::add_list(const gdp::session::FileList &list) {
	if (list.files_size() == 0 || !start()) {
		return {};
	}
	std::vector<std::string> paths = files_.add_list(list, true); // only ever sent with file-clipboard
	WLOG_INFO("files: the client copied %zu file(s)", paths.size());
	return paths;
}

void ClientFiles::share(const gdp::session::FileShare &share) {
	if (share.removed()) {
		auto it = share_paths_.find(share.share_id());
		if (it != share_paths_.end()) {
			if (bookmarks_) {
				remove_file_bookmarks(it->second);
			}
			share_paths_.erase(it);
		}
		files_.remove_share(share.share_id());
		return;
	}
	if (!start()) {
		return;
	}
	std::string path = files_.add_share(share.share_id(), share.name());
	if (path.empty()) {
		WLOG_INFO("files: refusing a shared folder named \"%s\"", share.name().c_str());
		return;
	}
	share_paths_[share.share_id()] = path;
	if (bookmarks_) {
		add_file_bookmark(path, share.name() + " (shared by the client)");
	}
	WLOG_INFO("files: the client shares \"%s\", at %s", share.name().c_str(), path.c_str());
}

void ClientFiles::answer(std::unique_ptr<gdp::Stream> stream, const gdp::session::FileAnswer &answer,
	std::vector<uint8_t> data) {
	files_.answer(answer.fetch_id(), std::move(stream), std::move(data));
}

} // namespace wraith
