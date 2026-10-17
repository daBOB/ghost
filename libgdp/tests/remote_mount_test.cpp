// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// gdp::RemoteMount on a real FUSE mount: this thread is the owner, feeding
// files in pieces as a peer would (with flow control), while another
// thread reads the mount through ordinary file calls. Covers a whole file
// read in order (one range), reads that jump about, a folder listed on
// request, a shared folder re-listed when stale, a file that fails, one
// shorter than listed, that nothing can be written, and that reading local
// folders leaves the mount out. Skipped where FUSE
// isn't built in or /dev/fuse can't be opened.
#include "gdp/remote_mount.hpp"

#include "gdp/file_list.hpp"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

std::atomic<int> g_failures{0};
#define CHECK(expr)                                                                                          \
	do {                                                                                                     \
		if (!(expr)) {                                                                                       \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #expr);                         \
			g_failures++;                                                                                    \
		}                                                                                                    \
	} while (0)

std::string pattern(size_t len, unsigned seed) {
	std::string out(len, '\0');
	uint32_t x = seed * 2654435761u + 1;
	for (size_t i = 0; i < len; i++) {
		x = x * 1103515245u + 12345u;
		out[i] = static_cast<char>(x >> 24);
	}
	return out;
}

std::string read_all(const std::string &path, int *error) {
	*error = 0;
	int fd = open(path.c_str(), O_RDONLY);
	if (fd < 0) {
		*error = errno;
		return "";
	}
	std::string out;
	char buf[128 * 1024];
	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			*error = errno;
			break;
		}
		if (n == 0) {
			break;
		}
		out.append(buf, static_cast<size_t>(n));
	}
	close(fd);
	return out;
}

std::vector<std::string> list_dir(const std::string &path) {
	std::vector<std::string> names;
	if (DIR *d = opendir(path.c_str())) {
		while (dirent *e = readdir(d)) {
			if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
				names.push_back(e->d_name);
			}
		}
		closedir(d);
	}
	return names;
}

// What the owner serves: file contents by key, and what one key's range
// may still send before FUSE takes some (the peer's stream window).
struct Range {
	uint64_t key;
	uint64_t offset;
	uint64_t credit;
};

} // namespace

int main() {
	if (!gdp::RemoteMount::supported()) {
		printf("remote_mount_test: skipped (built without FUSE)\n");
		return 0;
	}
	int probe = open("/dev/fuse", O_RDWR);
	if (probe < 0) {
		printf("remote_mount_test: skipped (/dev/fuse: %s)\n", strerror(errno));
		return 0;
	}
	close(probe);

	auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
	const std::string base = (std::filesystem::temp_directory_path() / ("gdp_remote_mount_" + std::to_string(stamp))).string();
	const std::string dir = base + "/mnt";

	const std::string big = pattern(6 << 20, 1), small = "small file\n", inner = "listed on request\n";
	std::map<uint64_t, std::string> contents = {{1, big}, {2, small}, {3, inner}, {5, std::string(500, 'x')}};
	const uint64_t kFailing = 4;
	const uint64_t kWindow = 1 << 20;

	gdp::RemoteMount mount;
	std::map<uint64_t, Range> ranges;
	uint64_t consumed_total = 0;
	int lists = 0, share_lists = 0;
	gdp::RemoteMount::Node lazy = 0, share = 0;
	mount.on_open_range = [&](uint64_t range, gdp::RemoteMount::Node, uint64_t key, uint64_t offset) {
		ranges[range] = {key, offset, kWindow};
	};
	mount.on_close_range = [&](uint64_t range) { ranges.erase(range); };
	mount.on_consumed = [&](uint64_t range, size_t bytes) {
		consumed_total += bytes;
		auto it = ranges.find(range);
		if (it != ranges.end()) {
			it->second.credit += bytes;
		}
	};
	mount.on_list = [&](gdp::RemoteMount::Node folder, uint64_t) {
		if (folder == lazy) {
			lists++;
			gdp::RemoteMount::Entry e;
			e.name = "inner.txt";
			e.size = inner.size();
			e.key = 3;
			mount.set_children(folder, {e});
		} else if (folder == share) {
			share_lists++;
			gdp::RemoteMount::Entry e;
			e.name = share_lists == 1 ? "first.txt" : "second.txt";
			e.size = small.size();
			e.key = 2;
			e.refresh_seconds = 0.2;
			mount.set_children(folder, {e});
		}
	};

	std::string error;
	if (!mount.mount(dir, &error)) {
		printf("remote_mount_test: skipped (can't mount: %s)\n", error.c_str());
		return 0;
	}
	CHECK(mount.contains(dir) && mount.contains(dir + "/clip/x") && !mount.contains(dir + "x"));
	CHECK(gdp::RemoteMount::available()); // it just mounted

	gdp::RemoteMount::Entry clip_e;
	clip_e.name = "clip";
	clip_e.directory = true;
	auto clip = mount.add(gdp::RemoteMount::kRoot, clip_e);
	auto add_file = [&](const char *name, uint64_t size, uint64_t key) {
		gdp::RemoteMount::Entry e;
		e.name = name;
		e.size = size;
		e.key = key;
		e.modified_unix_ms = 1700000000123;
		return mount.add(clip, e);
	};
	add_file("big.bin", big.size(), 1);
	add_file("small.txt", small.size(), 2);
	add_file("broken.bin", 1000, kFailing);
	add_file("short.bin", 1000, 5); // listed at 1000, only 500 come
	gdp::RemoteMount::Entry lazy_e;
	lazy_e.name = "lazy";
	lazy_e.directory = true;
	lazy_e.listed = false;
	lazy = mount.add(clip, lazy_e);
	gdp::RemoteMount::Entry share_e;
	share_e.name = "share";
	share_e.directory = true;
	share_e.listed = false;
	share_e.refresh_seconds = 0.2;
	share = mount.add(gdp::RemoteMount::kRoot, share_e);
	CHECK(mount.path_of(lazy) == dir + "/clip/lazy");
	CHECK(mount.child(clip, "small.txt") != 0 && mount.child(clip, "nope") == 0);

	std::atomic<bool> done{false};
	uint64_t opened_before_seq = 0, opened_after_seq = 0;
	std::thread reader([&] {
		auto step = [](const char *what) {
			if (getenv("GDP_TEST_TRACE")) {
				fprintf(stderr, "reader: %s\n", what);
			}
		};
		step("stat");
		struct stat st;
		CHECK(stat((dir + "/clip/big.bin").c_str(), &st) == 0 && st.st_size == (off_t)big.size());
		CHECK(S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0644 && st.st_mtim.tv_sec == 1700000000);
		CHECK(stat((dir + "/clip").c_str(), &st) == 0 && S_ISDIR(st.st_mode));
		CHECK(stat((dir + "/clip/missing").c_str(), &st) != 0 && errno == ENOENT);

		step("read in order");
		// In order, start to end: one range, the window refilled as it goes.
		opened_before_seq = mount.ranges_opened();
		int err;
		CHECK(read_all(dir + "/clip/big.bin", &err) == big && err == 0);
		opened_after_seq = mount.ranges_opened();

		step("read about");
		// Jumping about (a fresh descriptor; the page cache may answer some).
		int fd = open((dir + "/clip/big.bin").c_str(), O_RDONLY | O_DIRECT);
		if (fd < 0) {
			fd = open((dir + "/clip/big.bin").c_str(), O_RDONLY);
		}
		char buf[4096];
		for (uint64_t off : {uint64_t(5) << 20, uint64_t(4096), uint64_t(3) << 20, big.size() - 4096}) {
			CHECK(pread(fd, buf, sizeof(buf), (off_t)off) == (ssize_t)sizeof(buf));
			CHECK(memcmp(buf, big.data() + off, sizeof(buf)) == 0);
		}
		CHECK(pread(fd, buf, sizeof(buf), (off_t)big.size()) == 0);
		close(fd);

		step("small");
		CHECK(read_all(dir + "/clip/small.txt", &err) == small);
		step("lazy");
		// Listed on request, once.
		CHECK(list_dir(dir + "/clip/lazy") == std::vector<std::string>{"inner.txt"});
		CHECK(read_all(dir + "/clip/lazy/inner.txt", &err) == inner);
		step("share");
		// A shared folder: listed when first wanted, again once stale.
		CHECK(list_dir(dir + "/share") == std::vector<std::string>{"first.txt"});
		std::this_thread::sleep_for(std::chrono::milliseconds(400));
		CHECK(list_dir(dir + "/share") == std::vector<std::string>{"second.txt"});
		step("failing");
		// Failing, and shorter than listed.
		read_all(dir + "/clip/broken.bin", &err);
		CHECK(err == EIO);
		CHECK(read_all(dir + "/clip/short.bin", &err) == std::string(500, 'x') && err == 0);
		step("own mount");
		// The folder the mount is in (a share of $XDG_RUNTIME_DIR, or a copy
		// of it): the mount is left out without being looked at. Checked here,
		// where the owner still serves it, so that a regression fails rather
		// than hangs: on the owner's thread, looking would wait forever.
		CHECK(gdp::inside_own_mount(dir) && gdp::inside_own_mount(dir + "/clip/x") &&
			!gdp::inside_own_mount(dir + "x"));
		CHECK(gdp::read_local_folder(base).empty());
		CHECK(gdp::resolve_beneath(base, "mnt").empty() && gdp::resolve_beneath(dir, "").empty());
		gdp::LocalEntry own;
		CHECK(!gdp::stat_local(dir, &own, true));
		CHECK(gdp::LocalFileList::build(1, {base}, true).size() == 1);
		step("read-only");
		// Nothing goes in.
		CHECK(open((dir + "/clip/small.txt").c_str(), O_WRONLY) < 0 && errno == EROFS);
		CHECK(open((dir + "/clip/new.txt").c_str(), O_WRONLY | O_CREAT, 0644) < 0);
		CHECK(mkdir((dir + "/clip/newdir").c_str(), 0755) != 0);
		CHECK((list_dir(dir + "/clip") ==
			std::vector<std::string>{"big.bin", "small.txt", "broken.bin", "short.bin", "lazy"}));
		done = true;
	});

	// The owner: dispatch, and feed every open range 64 KiB at a time within
	// its credit, as a stream would.
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(60);
	while (!done && std::chrono::steady_clock::now() < deadline) {
		struct pollfd pfd = {mount.notify_fd(), POLLIN, 0};
		poll(&pfd, 1, ranges.empty() ? 50 : 1);
		mount.dispatch();
		std::vector<uint64_t> ids;
		for (auto &[id, r] : ranges) {
			ids.push_back(id);
		}
		for (uint64_t id : ids) {
			auto it = ranges.find(id);
			if (it == ranges.end()) {
				continue;
			}
			Range &r = it->second;
			if (r.key == kFailing) {
				ranges.erase(it);
				mount.range_end(id, EIO);
				continue;
			}
			const std::string &c = contents[r.key];
			size_t n = (size_t)std::min<uint64_t>({64 * 1024, r.credit, c.size() > r.offset ? c.size() - r.offset : 0});
			if (n > 0) {
				r.offset += n;
				r.credit -= n;
				mount.range_data(id, reinterpret_cast<const uint8_t *>(c.data() + r.offset - n), n);
			} else if (r.offset >= c.size()) {
				ranges.erase(id);
				mount.range_end(id, 0);
			}
		}
	}
	CHECK(done);
	if (!done) {
		mount.unmount(); // fails whatever the reader waits on, so it can be joined
	}
	reader.join();

	CHECK(opened_after_seq - opened_before_seq == 1);
	CHECK(lists == 1 && share_lists == 2);
	CHECK(consumed_total >= big.size());
	mount.unmount();
	CHECK(!mount.mounted());
	CHECK(!std::filesystem::exists(dir));
	CHECK(!gdp::inside_own_mount(dir));
	std::filesystem::remove(base);

	if (g_failures) {
		fprintf(stderr, "remote_mount_test: %d check(s) failed\n", g_failures.load());
		return 1;
	}
	printf("remote_mount_test: all passed\n");
	return 0;
}
