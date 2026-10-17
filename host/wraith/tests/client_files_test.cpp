// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The client's files on the host, end to end (gdp-spec.md §7.12,
// file-clipboard and file-share): spectre's LocalFiles answers wraith's
// FileFetches over loopback (the control stream carried by hand here),
// ClientFiles mounts what the client copied and the folder it shares, and
// another thread reads the mount like the session's file manager. Covers a
// copied folder tree, a large file, a shared folder listed on demand and
// again once stale, and the shared folder's sidebar entries coming and
// going. Skipped without FUSE.
#include "session/client_files.hpp"
#include "session/file_bookmarks.hpp"
#include "session/file_receiver.hpp"

#include "net/local_files.hpp"

#include "gdp/file_transfer.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <wayland-server-core.h>

#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::atomic<int> g_failures{0};
#define CHECK(expr)                                                                                          \
	do {                                                                                                     \
		if (!(expr)) {                                                                                       \
			fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #expr);                         \
			g_failures++;                                                                                    \
		}                                                                                                    \
	} while (0)

int64_t now_ms() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000 + ts.tv_nsec / 1'000'000;
}

std::string pattern(size_t len, unsigned seed) {
	std::string out(len, '\0');
	uint32_t x = seed * 2654435761u + 1;
	for (size_t i = 0; i < len; i++) {
		x = x * 1103515245u + 12345u;
		out[i] = static_cast<char>(x >> 24);
	}
	return out;
}

void write_file(const fs::path &path, const std::string &content) {
	std::ofstream(path, std::ios::binary) << content;
}

std::string read_file(const fs::path &path) {
	std::ifstream in(path, std::ios::binary);
	return std::string(std::istreambuf_iterator<char>(in), {});
}

std::map<std::string, std::string> snapshot(const fs::path &root) {
	std::map<std::string, std::string> out;
	for (auto &e : fs::recursive_directory_iterator(root)) {
		out[fs::relative(e.path(), root).string() + (e.is_directory() ? "/" : "")] =
			e.is_regular_file() ? read_file(e.path()) : "";
	}
	return out;
}

std::vector<std::string> names(const fs::path &dir) {
	std::vector<std::string> out;
	for (auto &e : fs::directory_iterator(dir)) {
		out.push_back(e.path().filename().string());
	}
	std::sort(out.begin(), out.end());
	return out;
}

} // namespace

int main() {
	if (!gdp::RemoteFiles::supported() || access("/dev/fuse", R_OK | W_OK) != 0) {
		printf("client_files_test: skipped (no FUSE)\n");
		return 0;
	}
	const std::string cert = "/tmp/wraith_client_files_cert.pem";
	const std::string key = "/tmp/wraith_client_files_key.pem";
	std::string cmd = "openssl req -x509 -newkey rsa:2048 -keyout " + key + " -out " + cert +
		" -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1";
	if (system(cmd.c_str()) != 0) {
		fprintf(stderr, "client_files_test: openssl failed\n");
		return 1;
	}
	char dir_template[] = "/tmp/wraith_client_files_XXXXXX";
	const fs::path dir = mkdtemp(dir_template);
	// The host user's runtime, config and data directories, all in here.
	fs::create_directories(dir / "run");
	fs::create_directories(dir / "data");
	setenv("XDG_RUNTIME_DIR", (dir / "run").c_str(), 1);
	setenv("XDG_CONFIG_HOME", (dir / "config").c_str(), 1);
	setenv("XDG_DATA_HOME", (dir / "data").c_str(), 1);
	write_file(dir / "data" / "user-places.xbel",
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<xbel>\n <bookmark href=\"file:///home/u\">\n  "
		"<title>Home</title>\n </bookmark>\n</xbel>\n");

	// What the client's user copies, and the folder they share.
	const fs::path src = dir / "client-copied", shared = dir / "client-shared", out = dir / "pasted";
	fs::create_directories(src / "photos" / "2024");
	write_file(src / "photos" / "big.raw", pattern(12 << 20, 4));
	write_file(src / "photos" / "2024" / "a.jpg", "jpeg a");
	write_file(src / "photos" / "2024" / "b.jpg", "jpeg b");
	write_file(src / "notes.txt", "notes\n");
	fs::create_directories(shared / "docs");
	write_file(shared / "docs" / "plan.md", "# plan\n");
	write_file(shared / "readme.txt", "shared readme\n");
	fs::create_directories(shared / ".secret");
	write_file(shared / ".secret" / "key", "private key\n");
	write_file(shared / ".env", "TOKEN=1\n");

	wl_event_loop *loop = wl_event_loop_create();
	// Destroyed last, after everything with a source on it.
	struct LoopGuard {
		wl_event_loop *loop;
		~LoopGuard() { wl_event_loop_destroy(loop); }
	} loop_guard{loop};
	gdp::Transport server, client;
	std::deque<gdp::session::FileFetch> control; // host -> client, carried by hand
	auto client_files = std::make_unique<wraith::ClientFiles>(
		loop, [&](const gdp::session::FileFetch &f) { control.push_back(f); }, true);
	wraith::FileReceiver receiver(loop, dir.string(), [](uint64_t code) { fprintf(stderr, "protocol error %llu\n", (unsigned long long)code); },
		[](const std::string &, const std::string &) {});
	receiver.on_answer = [&](std::unique_ptr<gdp::Stream> s, const gdp::session::FileAnswer &a,
							 std::vector<uint8_t> data) { client_files->answer(std::move(s), a, std::move(data)); };
	std::unique_ptr<gdp::Connection> server_conn;
	CHECK(server.listen(44381, "gdp-test/1", cert, key, [&](std::unique_ptr<gdp::Connection> c) {
		server_conn = std::move(c);
		server_conn->on_control_stream = [](gdp::Stream *) {};
		server_conn->on_input_stream = [](gdp::Stream *) {};
		server_conn->allow_streams(gdp::kFileStreamsAtOnce);
		server_conn->on_stream = [&](std::unique_ptr<gdp::Stream> s) { receiver.add_stream(std::move(s)); };
	}));
	auto conn = client.connect("127.0.0.1", 44381, "gdp-test/1");
	bool up = false;
	conn->on_state_changed = [&](gdp::ConnectionState s) { up = up || s == gdp::ConnectionState::kConnected; };
	spectre::LocalFiles local([&] { return conn->open_stream(); });

	auto spin = [&](int timeout_ms, const std::function<bool()> &done) {
		int64_t start = now_ms();
		while (!done()) {
			struct pollfd fds[3] = {{server.notify_fd(), POLLIN, 0}, {client.notify_fd(), POLLIN, 0},
				{wl_event_loop_get_fd(loop), POLLIN, 0}};
			poll(fds, 3, 5);
			server.dispatch();
			client.dispatch();
			wl_event_loop_dispatch(loop, 0);
			wl_event_loop_dispatch_idle(loop);
			while (!control.empty()) {
				gdp::session::FileFetch f = control.front();
				control.pop_front();
				local.answer(f);
			}
			if (now_ms() - start > timeout_ms) {
				return false;
			}
		}
		return true;
	};
	CHECK(spin(5000, [&] { return up; }));
	conn->open_control_stream();
	conn->open_input_stream();

	// The client copies; the host mounts the list and gets the paths it
	// would put on the session's clipboard.
	auto list = local.set_list({(src / "photos").string(), (src / "notes.txt").string()});
	CHECK(list.files_size() == 6 && local.has_list());
	std::vector<std::string> paths = client_files->add_list(list);
	const fs::path mnt = dir / "run" / "ghost" / "files";
	CHECK(paths.size() == 2 && paths[0] == (mnt / "clip" / "1" / "photos").string());
	CHECK(client_files->contains(paths[1]));

	// The session's file manager pastes them.
	std::atomic<int> step{0};
	std::thread paster([&] {
		fs::create_directories(out);
		for (const std::string &p : paths) {
			std::error_code ec;
			fs::copy(p, out / fs::path(p).filename(), fs::copy_options::recursive, ec);
			CHECK(!ec);
		}
		step = 1;
	});
	CHECK(spin(60000, [&] { return step.load() == 1; }));
	if (step != 1) {
		client_files.reset(); // unmounts, failing what the paster waits on
	}
	paster.join();
	CHECK(snapshot(src) == snapshot(out));

	// A shared folder: in the mount and the sidebar, listed when opened,
	// listed again once stale.
	std::string name;
	uint64_t share_id = local.add_share(shared.string(), false, &name);
	CHECK(share_id != 0 && name == "client-shared");
	gdp::session::FileShare share;
	share.set_share_id(share_id);
	share.set_name(name);
	client_files->share(share);
	const fs::path share_dir = mnt / "shares" / "client-shared";
	std::string gtk = read_file(wraith::gtk_bookmarks_path());
	CHECK(gtk.find(gdp::file_uri(share_dir.string()) + " client-shared (shared by the client)") != std::string::npos);
	std::string xbel = read_file(wraith::kde_places_path());
	CHECK(xbel.find("<bookmark href=\"" + gdp::file_uri(share_dir.string()) + "\">") != std::string::npos);
	CHECK(xbel.find("file:///home/u") != std::string::npos);

	std::vector<std::string> first, later;
	std::string plan;
	bool hidden_reached = true;
	std::thread browser([&] {
		first = names(share_dir);
		plan = read_file(share_dir / "docs" / "plan.md");
		// Hidden files are neither listed nor reachable by name.
		hidden_reached = fs::exists(share_dir / ".env") || fs::exists(share_dir / ".secret" / "key") ||
			!read_file(share_dir / ".secret" / "key").empty();
		write_file(shared / "added-later.txt", "new");
		std::this_thread::sleep_for(std::chrono::milliseconds(5500)); // past the listing's 5 s
		later = names(share_dir);
		step = 2;
	});
	CHECK(spin(30000, [&] { return step.load() == 2; }));
	if (step != 2) {
		client_files.reset();
	}
	browser.join();
	CHECK((first == std::vector<std::string>{"docs", "readme.txt"}));
	CHECK(plan == "# plan\n");
	CHECK(!hidden_reached);
	CHECK((later == std::vector<std::string>{"added-later.txt", "docs", "readme.txt"}));
	// Listing the share again kept its entries' keys: the copy's 6, the
	// share itself, docs, readme.txt, docs/plan.md and added-later.txt.
	CHECK(client_files->files().keys() == 11);

	// No longer shared: gone from the sidebar and the keys.
	gdp::session::FileShare unshare;
	unshare.set_share_id(share_id);
	unshare.set_removed(true);
	client_files->share(unshare);
	CHECK(read_file(wraith::gtk_bookmarks_path()).find("client-shared") == std::string::npos);
	CHECK(client_files->files().keys() == 6);

	// The session ends: unmounted, the sidebar entries gone, the user's own kept.
	client_files.reset();
	CHECK(!fs::exists(mnt));
	CHECK(read_file(wraith::gtk_bookmarks_path()).find("client-shared") == std::string::npos);
	xbel = read_file(wraith::kde_places_path());
	CHECK(xbel.find("client-shared") == std::string::npos && xbel.find("file:///home/u") != std::string::npos);

	conn.reset();
	server_conn.reset();
	fs::remove_all(dir);
	unlink(cert.c_str());
	unlink(key.c_str());
	if (g_failures) {
		fprintf(stderr, "client_files_test: %d check(s) failed\n", g_failures.load());
		return 1;
	}
	printf("client_files_test: all passed\n");
	return 0;
}
