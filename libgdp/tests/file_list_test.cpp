// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// gdp/file_list.hpp on a real folder tree: lists with and without folder
// contents, the byte budget, listings appended on request, and paths in a
// shared folder that must not lead out of it.
#include "gdp/file_list.hpp"

#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

void write_file(const fs::path &path, const std::string &content) {
	std::ofstream(path, std::ios::binary) << content;
}

std::string name(const gdp::session::FileList &list, int i) {
	return list.files(i).name();
}

} // namespace

int main() {
	auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
	fs::path root = fs::temp_directory_path() / ("gdp_file_list_test_" + std::to_string(stamp));
	fs::remove_all(root);
	fs::create_directories(root / "photos" / "sub");
	write_file(root / "a.txt", "hello");
	write_file(root / "photos" / "x.jpg", "jpeg!");
	write_file(root / "photos" / "sub" / "y", "");
	write_file(root / "photos" / "bad\nname", "skipped");
	fs::create_symlink("/etc/passwd", root / "photos" / "link");
	fs::create_symlink(root / "photos", root / "linked-folder");
	const std::string a = (root / "a.txt").string(), photos = (root / "photos").string();

	// What was copied only: the folder flagged, nothing inside it. A link
	// copied itself is followed (the user picked it); a missing path isn't.
	auto flat = gdp::LocalFileList::build(1, {a, photos, (root / "linked-folder").string(), "/nonexistent"}, false);
	assert(flat.list_id() == 1 && flat.size() == 3);
	assert(name(flat.listing(), 2) == "linked-folder" && flat.listing().files(2).directory());
	assert(flat.is_top_level(2) && flat.is_top_level(0));
	assert(name(flat.listing(), 0) == "a.txt" && flat.listing().files(0).size() == 5);
	assert(name(flat.listing(), 1) == "photos" && flat.listing().files(1).directory());
	assert(!flat.listing().files(1).unlisted() && flat.listing().files(1).parent() == 0);
	assert(flat.listing().files(0).modified_unix_ms() > 0);

	// With folder contents: breadth-first, sorted, parents by 1 + index,
	// links and unusable names left out.
	auto tree = gdp::LocalFileList::build(2, {a, photos}, true);
	const auto &t = tree.listing();
	assert(t.files_size() == 5);
	assert(name(t, 2) == "sub" && t.files(2).parent() == 2 && t.files(2).directory());
	assert(name(t, 3) == "x.jpg" && t.files(3).parent() == 2);
	assert(name(t, 4) == "y" && t.files(4).parent() == 3);
	for (int i = 0; i < t.files_size(); i++) {
		assert(!t.files(i).unlisted());
	}
	assert(tree.path(4) == (root / "photos" / "sub" / "y").string());
	assert(!tree.is_top_level(4));
	assert(tree.path(9).empty() && !tree.is_directory(9));

	// A budget only what was copied fits in: the folder unlisted, then
	// listed on request, its entries appended; asking again gives the same.
	auto small = gdp::LocalFileList::build(3, {a, photos}, true, 60);
	assert(small.size() == 2 && small.listing().files(1).unlisted());
	std::vector<gdp::session::FileListing> frames;
	assert(!small.list_folder(0, &frames)); // a file
	assert(small.list_folder(1, &frames) && frames.size() == 1);
	assert(frames[0].first_index() == 2 && frames[0].files_size() == 2);
	assert(frames[0].files(0).name() == "sub" && frames[0].files(0).unlisted());
	assert(frames[0].files(1).name() == "x.jpg" && frames[0].files(1).parent() == 2);
	assert(small.size() == 4 && !small.listing().files(1).unlisted());
	std::vector<gdp::session::FileListing> again;
	assert(small.list_folder(1, &again) && again.size() == 1 && again[0].first_index() == 2 &&
		again[0].files_size() == 2 && small.size() == 4);
	assert(small.list_folder(2, &frames) && frames[0].first_index() == 4 && frames[0].files(0).name() == "y");
	assert(small.listing().files(4).parent() == 3);
	// Frames split at their budget, numbering on.
	assert(small.list_folder(1, &frames, 30) && frames.size() == 2);
	assert(frames[0].first_index() == 2 && frames[1].first_index() == 3);
	// An empty folder answers with one empty frame.
	fs::create_directories(root / "empty");
	auto empty = gdp::LocalFileList::build(4, {(root / "empty").string()}, false);
	assert(empty.list_folder(0, &frames) && frames.size() == 1 && frames[0].files_size() == 0);

	// In two steps, the folder read elsewhere: appended once, then listed
	// without reading; a second read handed in after that changes nothing.
	auto two = gdp::LocalFileList::build(5, {a, photos}, true, 60);
	assert(!two.listed(0) && !two.add_folder(0, {})); // a file
	assert(!two.listed(1));
	std::vector<gdp::LocalEntry> read = gdp::read_local_folder(two.path(1));
	assert(two.add_folder(1, read) && two.listed(1) && two.size() == 4);
	assert(two.add_folder(1, read) && two.size() == 4);
	assert(two.list_folder(1, &frames) && frames[0].first_index() == 2 && frames[0].files_size() == 2);

	// Shared folder paths.
	const std::string r = root.string();
	assert(gdp::resolve_beneath(r, "") == r);
	assert(gdp::resolve_beneath(r, "photos/sub/y") == (root / "photos" / "sub" / "y").string());
	assert(gdp::resolve_beneath(r, "a.txt") == a);
	for (const char *bad : {"..", "../etc", "photos/../a.txt", "/etc", "photos//x.jpg", "photos/", "photos/link",
			 "linked-folder/x.jpg", "missing", "a.txt/more", "photos/./x.jpg"}) {
		assert(gdp::resolve_beneath(r, bad).empty());
	}
	assert(gdp::resolve_beneath(r + "/a.txt", "").empty()); // not a folder

	// Hidden files: kept unless asked otherwise, and then nothing beneath
	// a hidden folder either.
	fs::create_directories(root / ".ssh");
	std::ofstream(root / ".ssh" / "id_ed25519") << "key";
	std::ofstream(root / "photos" / ".hidden.jpg") << "h";
	assert(gdp::hidden_local((root / ".ssh").string()) && !gdp::hidden_local((root / "photos").string()));
	assert(gdp::resolve_beneath(r, ".ssh/id_ed25519") == (root / ".ssh" / "id_ed25519").string());
	assert(gdp::resolve_beneath(r, ".ssh/id_ed25519", false).empty());
	assert(gdp::resolve_beneath(r, ".ssh", false).empty());
	assert(gdp::resolve_beneath(r, "photos/.hidden.jpg", false).empty());
	assert(gdp::resolve_beneath(r, "photos/x.jpg", false) == (root / "photos" / "x.jpg").string());
	auto names_in = [](const std::vector<gdp::LocalEntry> &entries) {
		std::vector<std::string> out;
		for (const auto &e : entries) {
			out.push_back(e.name);
		}
		return out;
	};
	auto all = names_in(gdp::read_local_folder(r));
	auto shown = names_in(gdp::read_local_folder(r, false));
	assert(std::find(all.begin(), all.end(), ".ssh") != all.end());
	assert(std::find(shown.begin(), shown.end(), ".ssh") == shown.end() && shown.size() == all.size() - 1);

	fs::remove_all(root);
	printf("file_list_test: all passed\n");
	return 0;
}
