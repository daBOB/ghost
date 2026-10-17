// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/file_list.hpp"

#include "gdp/remote_mount.hpp"

#include <algorithm>
#include <chrono>
#include <deque>
#include <filesystem>
#include <system_error>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/stat.h>
#endif

namespace gdp {

namespace fs = std::filesystem;

namespace {

// Every path here is UTF-8, which std::filesystem takes only through
// u8string (Windows would read a plain string in the ANSI code page).
fs::path fs_path(const std::string &utf8) {
	return fs::path(std::u8string(utf8.begin(), utf8.end()));
}

std::string utf8_path(const fs::path &path) {
	std::u8string s = path.u8string();
	return std::string(s.begin(), s.end());
}

// file_clock's epoch is the library's to choose: through both clocks' now().
int64_t unix_ms(fs::file_time_type written) {
	auto since = written - fs::file_time_type::clock::now();
	auto when = std::chrono::system_clock::now() + std::chrono::duration_cast<std::chrono::system_clock::duration>(since);
	return std::chrono::duration_cast<std::chrono::milliseconds>(when.time_since_epoch()).count();
}

bool entry_of(const fs::directory_entry &de, LocalEntry *entry, bool follow = false) {
	std::error_code ec;
	fs::file_status st = follow ? de.status(ec) : de.symlink_status(ec);
	if (ec || !(fs::is_regular_file(st) || fs::is_directory(st))) {
		return false; // links (not followed), devices, sockets
	}
	entry->name = utf8_path(de.path().filename());
	if (!valid_file_name(entry->name)) {
		return false;
	}
	entry->directory = fs::is_directory(st);
	entry->size = entry->directory ? 0 : fs::file_size(de.path(), ec);
	if (ec) {
		return false;
	}
	auto written = fs::last_write_time(de.path(), ec);
	entry->modified_unix_ms = ec ? 0 : unix_ms(written);
	return true;
}

// Windows reads more into a name than §7.12 rules out: "a:b" is a stream
// of "a", and CON, NUL, COM1 and the like are devices in any folder.
bool windows_safe(const std::string &part) {
#ifdef _WIN32
	if (part.find(':') != std::string::npos || part.back() == '.' || part.back() == ' ') {
		return false;
	}
	std::string stem = part.substr(0, part.find('.'));
	for (char &c : stem) {
		c = static_cast<char>(c >= 'a' && c <= 'z' ? c - 32 : c);
	}
	for (const char *device : {"CON", "PRN", "AUX", "NUL"}) {
		if (stem == device) {
			return false;
		}
	}
	if (stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) && stem[3] >= '0' &&
		stem[3] <= '9') {
		return false;
	}
#else
	(void)part;
#endif
	return true;
}

// What an entry adds to an encoded list: itself, its tag and its length.
size_t encoded_size(const session::FileListEntry &e) {
	return e.ByteSizeLong() + 4;
}

} // namespace

session::FileListEntry to_list_entry(const LocalEntry &entry) {
	session::FileListEntry e;
	e.set_name(entry.name);
	e.set_size(entry.size);
	e.set_modified_unix_ms(entry.modified_unix_ms);
	e.set_directory(entry.directory);
	return e;
}

bool stat_local(const std::string &path, LocalEntry *entry, bool follow) {
	if (inside_own_mount(path)) {
		return false; // the other end's files, which this thread may be serving
	}
	std::error_code ec;
	fs::directory_entry de(fs_path(path), ec);
	return !ec && entry_of(de, entry, follow);
}

bool hidden_local(const std::string &path) {
	fs::path p = fs_path(path);
	std::u8string name = p.filename().u8string();
	if (!name.empty() && name[0] == u8'.') {
		return true;
	}
#ifdef _WIN32
	DWORD attributes = GetFileAttributesW(p.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES &&
		(attributes & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) != 0;
#elif defined(__APPLE__)
	struct stat st;
	return lstat(p.c_str(), &st) == 0 && (st.st_flags & UF_HIDDEN) != 0;
#else
	return false;
#endif
}

std::vector<LocalEntry> read_local_folder(const std::string &path, bool include_hidden) {
	std::vector<LocalEntry> entries;
	std::error_code ec;
	for (fs::directory_iterator it(fs_path(path), fs::directory_options::skip_permission_denied, ec), end;
		 !ec && it != end; it.increment(ec)) {
		LocalEntry entry;
		std::string child = utf8_path(it->path());
		// One of our own mounts (a share of $XDG_RUNTIME_DIR, say) is left out
		// before it is looked at: this thread may be the one serving it.
		if (inside_own_mount(child) || (!include_hidden && hidden_local(child))) {
			continue;
		}
		if (entry_of(*it, &entry)) {
			entries.push_back(std::move(entry));
		}
	}
	std::sort(entries.begin(), entries.end(),
		[](const LocalEntry &a, const LocalEntry &b) { return a.name < b.name; });
	return entries;
}

LocalFileList LocalFileList::build(uint64_t list_id, const std::vector<std::string> &paths, bool tree,
	size_t budget) {
	LocalFileList list;
	list.listing_.set_list_id(list_id);
	for (const std::string &path : paths) {
		if (list.paths_.size() == kMaxFileListEntries) {
			break;
		}
		LocalEntry entry;
		if (!stat_local(path, &entry, true)) {
			continue;
		}
		*list.listing_.add_files() = to_list_entry(entry);
		list.paths_.push_back(path);
		list.children_.emplace_back();
	}
	if (!tree) {
		return list;
	}
	// Breadth-first: what was copied, then what is in it, a level at a time,
	// until a folder's entries no longer fit.
	size_t used = list.listing_.ByteSizeLong();
	std::deque<uint32_t> folders;
	for (uint32_t i = 0; i < list.paths_.size(); i++) {
		if (list.is_directory(i)) {
			folders.push_back(i);
		}
	}
	bool full = false;
	while (!folders.empty()) {
		uint32_t index = folders.front();
		folders.pop_front();
		std::vector<LocalEntry> entries;
		if (!full) {
			entries = read_local_folder(list.paths_[index]);
			size_t more = 0;
			for (const LocalEntry &e : entries) {
				more += encoded_size(to_list_entry(e)) + 6; // parent and unlisted
			}
			full = used + more > budget || list.paths_.size() + entries.size() > kMaxFileListTotal;
			if (!full) {
				used += more;
			}
		}
		if (full) {
			list.listing_.mutable_files(index)->set_unlisted(true);
			continue;
		}
		uint32_t first = static_cast<uint32_t>(list.paths_.size());
		list.append_children(index, entries);
		for (uint32_t i = first; i < list.paths_.size(); i++) {
			if (list.is_directory(i)) {
				folders.push_back(i);
			}
		}
	}
	return list;
}

const std::string &LocalFileList::path(uint32_t index) const {
	static const std::string none;
	return index < paths_.size() ? paths_[index] : none;
}

bool LocalFileList::is_directory(uint32_t index) const {
	return index < paths_.size() && listing_.files(static_cast<int>(index)).directory();
}

bool LocalFileList::is_top_level(uint32_t index) const {
	return index < paths_.size() && listing_.files(static_cast<int>(index)).parent() == 0;
}

void LocalFileList::append_children(uint32_t index, const std::vector<LocalEntry> &entries) {
	children_[index].first = static_cast<uint32_t>(paths_.size());
	children_[index].count = static_cast<uint32_t>(entries.size());
	listing_.mutable_files(static_cast<int>(index))->set_unlisted(false);
	for (const LocalEntry &e : entries) {
		session::FileListEntry entry = to_list_entry(e);
		entry.set_parent(index + 1);
		// Not listed yet; build() and list_folder() clear it for those they read.
		entry.set_unlisted(e.directory);
		*listing_.add_files() = std::move(entry);
		paths_.push_back(utf8_path(fs_path(paths_[index]) / fs_path(e.name)));
		children_.emplace_back();
	}
}

bool LocalFileList::list_folder(uint32_t index, std::vector<session::FileListing> *frames, size_t frame_budget) {
	frames->clear();
	if (!is_directory(index)) {
		return false;
	}
	if (children_[index].first == UINT32_MAX) {
		std::vector<LocalEntry> entries = read_local_folder(paths_[index]);
		if (paths_.size() + entries.size() > kMaxFileListTotal) {
			return false;
		}
		append_children(index, entries);
	}
	const Children &c = children_[index];
	session::FileListing frame;
	frame.set_first_index(c.first);
	size_t used = 16;
	for (uint32_t i = c.first; i < c.first + c.count; i++) {
		const session::FileListEntry &entry = listing_.files(static_cast<int>(i));
		size_t more = encoded_size(entry);
		if (frame.files_size() > 0 && used + more > frame_budget) {
			frames->push_back(std::move(frame));
			frame = session::FileListing();
			frame.set_first_index(i);
			used = 16;
		}
		*frame.add_files() = entry;
		used += more;
	}
	frames->push_back(std::move(frame));
	return true;
}

std::string resolve_beneath(const std::string &root, const std::string &relative, bool include_hidden) {
	if (inside_own_mount(root)) {
		return "";
	}
	fs::path path = fs_path(root);
	std::error_code ec;
	fs::file_status st = fs::symlink_status(path, ec);
	if (ec || !fs::is_directory(st)) {
		return "";
	}
	size_t start = 0;
	while (start < relative.size()) {
		size_t slash = relative.find('/', start);
		std::string part = relative.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
		if (!valid_file_name(part) || !windows_safe(part)) {
			return ""; // empty parts, ".", "..", separators and control characters
		}
		path /= fs_path(part);
		if (inside_own_mount(utf8_path(path))) {
			return "";
		}
		st = fs::symlink_status(path, ec);
		if (ec || fs::is_symlink(st) || !(fs::is_directory(st) || fs::is_regular_file(st))) {
			return "";
		}
		if (!include_hidden && hidden_local(utf8_path(path))) {
			return "";
		}
		if (slash == std::string::npos) {
			break;
		}
		start = slash + 1;
		if (start == relative.size()) {
			return ""; // a trailing '/'
		}
	}
	return utf8_path(path);
}

} // namespace gdp
