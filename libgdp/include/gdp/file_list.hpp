// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// The side whose user copied files (gdp-spec.md §7.12) keeps each list it
// sent with the local path behind every entry, to answer requests by index:
// LocalFileList. The same end's shared folders (file-share) are answered by
// path, through resolve_beneath(). Portable (std::filesystem): the host and
// every client build lists the same way.
#pragma once

#include "gdp/file_transfer.hpp"
#include "session.pb.h"

#include <cstdint>
#include <string>
#include <vector>

namespace gdp {

// One thing in a local folder, as a list shows it.
struct LocalEntry {
	std::string name;
	bool directory = false;
	uint64_t size = 0;
	int64_t modified_unix_ms = 0;
};

// What `entry` looks like on the wire (parent 0, listed).
session::FileListEntry to_list_entry(const LocalEntry &entry);

// The local file or folder at `path` (UTF-8). False if it is neither (a
// device, gone, a symbolic link unless `follow`, or inside one of this
// process's own mounts) or its name breaks §7.12's rules. Something the user copied is followed (they picked the
// link, and mean what it points at); nothing found inside a folder is.
bool stat_local(const std::string &path, LocalEntry *entry, bool follow = false);

// Whether the local file or folder at `path` (UTF-8) is hidden the way this
// platform's file manager hides it: a name starting with '.' everywhere,
// and also the hidden or system attribute on Windows, UF_HIDDEN on macOS.
bool hidden_local(const std::string &path);

// What is in the local folder at `path`, sorted by name: regular files and
// folders with usable names only, none of this process's own mounts
// (inside_own_mount()), and no hidden ones unless `include_hidden`. Symbolic links are left out, so nothing reached through
// a list or a share leads outside what the user picked.
std::vector<LocalEntry> read_local_folder(const std::string &path, bool include_hidden = true);

class LocalFileList {
public:
	LocalFileList() = default;

	// The list for `paths`, what the user copied (UTF-8, absolute), in order:
	// at most kMaxFileListEntries of them, those stat_local() takes
	// (following a link: it was copied itself). With
	// `tree` (file-clipboard), what is in the folders follows, breadth-first,
	// a folder's entries all or none, while the encoded list stays within
	// `budget` bytes; a folder whose contents didn't fit is `unlisted`.
	static LocalFileList build(uint64_t list_id, const std::vector<std::string> &paths, bool tree,
		size_t budget = kFileListBudgetBytes);

	const session::FileList &listing() const { return listing_; }
	uint64_t list_id() const { return listing_.list_id(); }
	size_t size() const { return paths_.size(); }
	// Entry `index`'s local path; empty past the end.
	const std::string &path(uint32_t index) const;
	bool is_directory(uint32_t index) const;
	// Whether entry `index` is one of the things copied, not inside one:
	// only those may be reached through a symbolic link.
	bool is_top_level(uint32_t index) const;

	// The contents of folder `index` as FileListing frames, each within
	// `frame_budget` bytes encoded (one, empty, for an empty folder). A
	// folder not yet listed is read now and its entries appended to the list;
	// one listed already is answered from the list. False if `index` isn't
	// a folder, or the list would grow past kMaxFileListTotal.
	bool list_folder(uint32_t index, std::vector<session::FileListing> *frames,
		size_t frame_budget = kFileListBudgetBytes);

private:
	// Appends `entries` as the contents of folder `index` (1-based parent).
	void append_children(uint32_t index, const std::vector<LocalEntry> &entries);

	session::FileList listing_;
	std::vector<std::string> paths_;
	// Per folder entry: where its contents start in the list and how many,
	// once listed (first == UINT32_MAX: not listed).
	struct Children {
		uint32_t first = UINT32_MAX;
		uint32_t count = 0;
	};
	std::vector<Children> children_;
};

// A shared folder's `relative` path (gdp-spec.md §7.12: '/'-separated, each
// part a valid name, "" for the folder itself) as a local path beneath
// `root`, or "" if a part breaks the rules or anything on the way is a
// symbolic link -- nothing a request names may lead outside `root` -- or is
// one of this process's own mounts, or, unless `include_hidden`, is hidden
// (hidden_local()).
std::string resolve_beneath(const std::string &root, const std::string &relative, bool include_hidden = true);

} // namespace gdp
