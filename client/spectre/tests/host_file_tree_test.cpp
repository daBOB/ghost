// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// HostFileTree: a host FileList as Explorer's file descriptors want it --
// nested folders parents first, names Windows can't hold and paths too long
// left out with what they hold, unlisted folders filled in -- and
// gdp::windows_safe(), which it names files by. Plain assert(), as in
// libgdp/tests.
#include "net/host_file_tree.hpp"

#include "gdp/file_list.hpp"
#include "gdp/file_transfer.hpp"

#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

using spectre::HostFileTree;

namespace {

gdp::session::FileListEntry *add(gdp::session::FileList *list, const std::string &name, uint32_t parent,
	bool directory = false, uint64_t size = 0) {
	gdp::session::FileListEntry *e = list->add_files();
	e->set_name(name);
	e->set_parent(parent);
	e->set_directory(directory);
	e->set_size(size);
	e->set_modified_unix_ms(1700000000000);
	return e;
}

std::vector<std::string> paths(const std::vector<HostFileTree::File> &files) {
	std::vector<std::string> out;
	for (const HostFileTree::File &f : files) {
		out.push_back(f.path);
	}
	return out;
}

void test_windows_safe() {
	assert(gdp::windows_safe("report.pdf"));
	assert(gdp::windows_safe(".bashrc"));
	assert(gdp::windows_safe("CONSOLE.txt") && gdp::windows_safe("COM10") && gdp::windows_safe("LPT"));
	assert(!gdp::windows_safe("a:b"));
	assert(!gdp::windows_safe("trailing.") && !gdp::windows_safe("trailing "));
	assert(!gdp::windows_safe("CON") && !gdp::windows_safe("nul.txt") && !gdp::windows_safe("Com1.log"));
	assert(!gdp::windows_safe("lpt9") && !gdp::windows_safe("aux.tar.gz"));
	assert(!gdp::windows_safe(""));
}

void test_nested() {
	gdp::session::FileList list;
	list.set_list_id(9);
	add(&list, "a.txt", 0, false, 5);   // 0
	add(&list, "photos", 0, true);      // 1
	add(&list, "sub", 2, true);         // 2
	add(&list, "x.jpg", 2, false, 100); // 3
	add(&list, "y.jpg", 3, false, 7);   // 4
	add(&list, "empty", 3, true);       // 5
	HostFileTree tree(list, true);
	assert(tree.list_id() == 9 && tree.unlisted().empty());
	std::vector<HostFileTree::File> files = tree.files();
	std::vector<std::string> want = {"a.txt", "photos", "photos\\sub", "photos\\sub\\y.jpg", "photos\\sub\\empty",
		"photos\\x.jpg"};
	assert(paths(files) == want);
	assert(files[0].size == 5 && !files[0].directory && files[0].index == 0);
	assert(files[1].directory && files[1].size == 0 && files[1].index == 1);
	assert(files[3].index == 4 && files[3].name == "y.jpg" && files[3].modified_unix_ms == 1700000000000);
	assert(files[5].index == 3 && files[5].size == 100);

	// Without file-clipboard, folders can't be had.
	HostFileTree flat(list, false);
	assert(paths(flat.files()) == std::vector<std::string>{"a.txt"});
}

void test_dropped() {
	gdp::session::FileList list;
	add(&list, "ok", 0, true);                     // 0
	add(&list, "CON", 0, true);                    // 1: and what is in it
	add(&list, "inside", 2);                       // 2
	add(&list, "a:b", 1);                          // 3
	add(&list, "Same.txt", 1);                     // 4
	add(&list, "same.TXT", 1);                     // 5: taken, ignoring case
	std::string deep(120, 'd');
	add(&list, deep, 1, true);                     // 6
	add(&list, deep, 7, true);                     // 7: ok\ + 120 + \ + 120 = 244
	add(&list, std::string(15, 'f'), 8);           // 8: 260, 261 with its NUL: too long
	add(&list, std::string(14, 'f'), 8);           // 9: 259, and the NUL fits
	add(&list, "z", 1000);                         // 10: a parent after it: ignored
	HostFileTree tree(list, true);
	std::vector<std::string> dropped;
	std::vector<HostFileTree::File> files = tree.files(&dropped);
	std::vector<std::string> want = {"ok", "ok\\Same.txt", "ok\\" + deep, "ok\\" + deep + "\\" + deep,
		"ok\\" + deep + "\\" + deep + "\\" + std::string(14, 'f')};
	assert(paths(files) == want);
	assert(dropped.size() == 4);
	assert(dropped[0] == "CON: a name Windows can't hold");
	assert(dropped[1] == "ok\\a:b: a name Windows can't hold");
	assert(dropped[2] == "ok\\same.TXT: a name taken already in its folder");
	assert(dropped[3].find("a path too long") != std::string::npos);

	// UTF-16 lengths: two-, three- and four-byte characters.
	assert(spectre::utf16_units("\xC3\xA9\xE2\x82\xAC\xF0\x9F\x98\x80") == 4);
}

void test_unlisted() {
	gdp::session::FileList list;
	list.set_list_id(3);
	add(&list, "top", 0, true)->set_unlisted(true); // 0
	add(&list, "bad:", 0, true)->set_unlisted(true); // 1: never asked for
	HostFileTree tree(list, true);
	assert(tree.unlisted() == std::vector<uint32_t>{0});

	std::vector<uint32_t> asked;
	auto list_folder = [&](uint32_t index, uint32_t, std::vector<gdp::session::FileListing> *frames) {
		asked.push_back(index);
		gdp::session::FileListing l;
		if (index == 0) {
			l.set_first_index(2);
			l.add_files()->set_name("f");
			gdp::session::FileListEntry *d = l.add_files();
			d->set_name("deeper");
			d->set_directory(true);
			d->set_unlisted(true);
			// Two frames: the second takes up where the first left off.
			frames->push_back(l);
			l = gdp::session::FileListing();
			l.set_first_index(4);
			l.add_files()->set_name("g");
		} else if (index == 3) {
			l.set_first_index(5);
			l.add_files()->set_name("h");
		} else {
			return false;
		}
		frames->push_back(l);
		return true;
	};
	std::string why;
	assert(tree.fill(list_folder, std::chrono::steady_clock::now() + std::chrono::seconds(10), &why));
	assert((asked == std::vector<uint32_t>{0, 3}));
	assert(tree.size() == 6 && tree.unlisted().empty());
	std::vector<std::string> want = {"top", "top\\f", "top\\deeper", "top\\deeper\\h", "top\\g"};
	assert(paths(tree.files()) == want);
	assert(!tree.add_listing(0, {})); // listed already
	assert(!tree.add_listing(2, {})); // a file

	// A listing that fails, and a deadline gone.
	HostFileTree failing(list, true);
	assert(!failing.fill([](uint32_t, uint32_t, std::vector<gdp::session::FileListing> *) { return false; },
		std::chrono::steady_clock::now() + std::chrono::seconds(10), &why));
	assert(why == "the host didn't list top");
	HostFileTree late(list, true);
	assert(!late.fill(list_folder, std::chrono::steady_clock::now() - std::chrono::seconds(1), &why));

	// Past the total.
	HostFileTree big(list, true);
	gdp::session::FileListing huge;
	huge.set_first_index(2);
	for (size_t i = 0; i < gdp::kMaxFileListTotal; i++) {
		huge.add_files()->set_name("n" + std::to_string(i));
	}
	assert(!big.add_listing(0, {huge}));
}

} // namespace

int main() {
	test_windows_safe();
	test_nested();
	test_dropped();
	test_unlisted();
	std::printf("host_file_tree_test: ok\n");
	return 0;
}
