// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// HostFileTree: one of the host's FileLists (gdp-spec.md §7.12) as a file
// manager without FUSE takes it: every file and folder at once, each named
// by its path from where it is pasted ("photos\sub\y.jpg"), parents before
// children -- Explorer's FILEGROUPDESCRIPTORW. The folders the list leaves
// unlisted are asked for first (fill()), since such a paste wants the
// whole tree up front.
//
// Pure: what to ask the host is the caller's (HostFileReads), so this
// builds and is tested anywhere.
#pragma once

#include "session.pb.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

namespace spectre {

class HostFileTree {
public:
	// FILEDESCRIPTORW.cFileName's length, its NUL included.
	static constexpr size_t kMaxPathUnits = 260;

	// `tree`: file-clipboard is in effect. Without it the host can't say
	// what is in a folder, and folders are left out rather than pasted empty.
	HostFileTree(const gdp::session::FileList &list, bool tree);

	uint64_t list_id() const { return list_id_; }
	// Entries known, listings included.
	size_t size() const { return entries_.size(); }

	struct File {
		std::string path; // UTF-8, '\\'-separated, from the paste target
		std::string name; // its last part
		bool directory = false;
		uint64_t size = 0;
		int64_t modified_unix_ms = 0; // 0 = unknown
		uint32_t index = 0;           // in the host's list: what a FileRequest names
	};
	// Everything reachable from what was copied, parents first, folders'
	// entries in the host's order. Left out, and named in `dropped` if
	// given, with all they hold: what Windows can't name
	// (gdp::windows_safe()), a name taken already in the same folder
	// (ignoring ASCII case, as Windows does), and paths longer than
	// kMaxPathUnits UTF-16 units with their NUL.
	std::vector<File> files(std::vector<std::string> *dropped = nullptr) const;

	// The unlisted folders among files(): what fill() asks for.
	std::vector<uint32_t> unlisted() const;
	// Folder `index`'s contents, as the host answered a FileListingRequest
	// for it. False if `index` isn't an unlisted folder or the tree would
	// grow past gdp::kMaxFileListTotal entries.
	bool add_listing(uint32_t index, const std::vector<gdp::session::FileListing> &frames);

	// Asks for the folder at an index: its listing, waiting at most
	// `timeout_ms`; false if it failed.
	using ListFolder =
		std::function<bool(uint32_t index, uint32_t timeout_ms, std::vector<gdp::session::FileListing> *frames)>;
	// Lists every unlisted folder, and those found in them, until none is
	// left. False, with why, if a listing fails, the tree grows past
	// gdp::kMaxFileListTotal, or `deadline` passes first: then nothing is
	// pasted rather than half a tree.
	bool fill(const ListFolder &list_folder, std::chrono::steady_clock::time_point deadline, std::string *why);

private:
	void walk(std::vector<File> *files, std::vector<uint32_t> *unlisted, std::vector<std::string> *dropped) const;

	uint64_t list_id_ = 0;
	bool tree_ = false;
	std::map<uint32_t, gdp::session::FileListEntry> entries_; // by index in the host's list
};

// How many UTF-16 code units the valid UTF-8 `s` comes to.
size_t utf16_units(const std::string &s);

} // namespace spectre
