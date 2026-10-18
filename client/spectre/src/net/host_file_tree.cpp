// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/host_file_tree.hpp"

#include "gdp/file_list.hpp"
#include "gdp/file_transfer.hpp"

#include <algorithm>
#include <set>
#include <utility>

namespace spectre {

namespace {

std::string ascii_lower(const std::string &s) {
	std::string out = s;
	for (char &c : out) {
		c = static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c);
	}
	return out;
}

} // namespace

size_t utf16_units(const std::string &s) {
	size_t n = 0;
	for (unsigned char c : s) {
		if ((c & 0xC0) != 0x80) {
			n += c >= 0xF0 ? 2 : 1; // four bytes: a surrogate pair
		}
	}
	return n;
}

HostFileTree::HostFileTree(const gdp::session::FileList &list, bool tree) : list_id_(list.list_id()), tree_(tree) {
	for (int i = 0; i < list.files_size(); i++) {
		entries_[static_cast<uint32_t>(i)] = list.files(i);
	}
}

void HostFileTree::walk(std::vector<File> *files, std::vector<uint32_t> *unlisted,
	std::vector<std::string> *dropped) const {
	std::map<uint32_t, std::vector<uint32_t>> children; // parent (1 + index, 0: copied) -> entries
	for (const auto &[index, e] : entries_) {
		// A parent is listed before its children (§7.12); one that isn't
		// would be a loop.
		if (e.parent() == 0 || e.parent() - 1 < index) {
			children[e.parent()].push_back(index);
		}
	}
	struct Item {
		uint32_t index;
		std::string path;
	};
	// The entries of folder `parent` worth keeping, in order.
	auto take = [&](uint32_t parent, const std::string &under) {
		std::vector<Item> kept;
		auto it = children.find(parent);
		if (it == children.end()) {
			return kept;
		}
		std::set<std::string> names;
		for (uint32_t index : it->second) {
			const gdp::session::FileListEntry &e = entries_.at(index);
			if (e.directory() && !tree_) {
				continue; // can't be had: not shown at all, as the mount does
			}
			std::string path = under.empty() ? e.name() : under + "\\" + e.name();
			const char *why = nullptr;
			if (!gdp::valid_file_name(e.name()) || !gdp::windows_safe(e.name())) {
				why = "a name Windows can't hold";
			} else if (!names.insert(ascii_lower(e.name())).second) {
				why = "a name taken already in its folder";
			} else if (utf16_units(path) + 1 > kMaxPathUnits) {
				why = "a path too long";
			}
			if (why) {
				if (dropped) {
					dropped->push_back(path + ": " + why);
				}
				continue;
			}
			kept.push_back({index, std::move(path)});
		}
		return kept;
	};

	std::vector<Item> stack = take(0, "");
	std::reverse(stack.begin(), stack.end());
	while (!stack.empty()) {
		Item item = std::move(stack.back());
		stack.pop_back();
		const gdp::session::FileListEntry &e = entries_.at(item.index);
		if (e.directory() && e.unlisted() && unlisted) {
			unlisted->push_back(item.index);
		}
		if (e.directory()) {
			std::vector<Item> under = take(item.index + 1, item.path);
			for (auto it = under.rbegin(); it != under.rend(); ++it) {
				stack.push_back(std::move(*it));
			}
		}
		if (files) {
			File f;
			f.name = e.name();
			f.path = std::move(item.path);
			f.directory = e.directory();
			f.size = e.directory() ? 0 : e.size();
			f.modified_unix_ms = e.modified_unix_ms();
			f.index = item.index;
			files->push_back(std::move(f));
		}
	}
}

std::vector<HostFileTree::File> HostFileTree::files(std::vector<std::string> *dropped) const {
	std::vector<File> out;
	walk(&out, nullptr, dropped);
	return out;
}

std::vector<uint32_t> HostFileTree::unlisted() const {
	std::vector<uint32_t> out;
	walk(nullptr, &out, nullptr);
	return out;
}

bool HostFileTree::add_listing(uint32_t index, const std::vector<gdp::session::FileListing> &frames) {
	auto folder = entries_.find(index);
	if (folder == entries_.end() || !folder->second.directory() || !folder->second.unlisted()) {
		return false;
	}
	size_t more = 0;
	for (const gdp::session::FileListing &l : frames) {
		more += static_cast<size_t>(l.files_size());
	}
	if (entries_.size() + more > gdp::kMaxFileListTotal) {
		return false;
	}
	folder->second.set_unlisted(false);
	for (const gdp::session::FileListing &l : frames) {
		for (int i = 0; i < l.files_size(); i++) {
			uint32_t at = l.first_index() + static_cast<uint32_t>(i);
			if (at <= index || entries_.count(at)) {
				continue; // an index the list already gave: not this folder's
			}
			gdp::session::FileListEntry e = l.files(i);
			e.set_parent(index + 1);
			// What is in its folders isn't, until they are listed too.
			e.set_unlisted(e.directory());
			entries_[at] = std::move(e);
		}
	}
	return true;
}

bool HostFileTree::fill(const ListFolder &list_folder, std::chrono::steady_clock::time_point deadline,
	std::string *why) {
	for (;;) {
		std::vector<uint32_t> folders = unlisted();
		if (folders.empty()) {
			return true;
		}
		for (uint32_t index : folders) {
			auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
				deadline - std::chrono::steady_clock::now());
			if (left.count() <= 0) {
				*why = "listing its folders took too long";
				return false;
			}
			std::vector<gdp::session::FileListing> frames;
			if (!list_folder(index, static_cast<uint32_t>(left.count()), &frames)) {
				*why = "the host didn't list " + entries_.at(index).name();
				return false;
			}
			if (!add_listing(index, frames)) {
				*why = "more than " + std::to_string(gdp::kMaxFileListTotal) + " files";
				return false;
			}
		}
	}
}

} // namespace spectre
