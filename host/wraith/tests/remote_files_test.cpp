// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Paste of the host's copied files, end to end (gdp-spec.md §7.12,
// file-clipboard): wraith's FileSender behind a FileReceiver serves a
// copied folder tree over loopback; a client's gdp::RemoteFiles mounts it
// with FUSE, opening a stream per request as spectre does; another thread
// copies the tree out of the mount like a file manager, and it must come out
// the same. Covers a folder too big for the list (listed on request), a
// large file (one range, read ahead), an earlier list still readable after a
// new copy, and cancelling a read part way. Skipped without FUSE.
#include "session/file_receiver.hpp"
#include "session/file_sender.hpp"

#include "gdp/file_transfer.hpp"
#include "gdp/framing.hpp"
#include "gdp/remote_files.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <wayland-server-core.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
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

// Every regular file under `root`, by relative path, with its contents.
std::map<std::string, std::string> snapshot(const fs::path &root) {
	std::map<std::string, std::string> out;
	for (auto &e : fs::recursive_directory_iterator(root)) {
		if (e.is_regular_file()) {
			out[fs::relative(e.path(), root).string()] = read_file(e.path());
		} else if (e.is_directory()) {
			out[fs::relative(e.path(), root).string() + "/"] = "";
		}
	}
	return out;
}

} // namespace

int main() {
	if (!gdp::RemoteFiles::supported() || access("/dev/fuse", R_OK | W_OK) != 0) {
		printf("remote_files_test: skipped (no FUSE)\n");
		return 0;
	}
	const std::string cert = "/tmp/wraith_remote_files_cert.pem";
	const std::string key = "/tmp/wraith_remote_files_key.pem";
	std::string cmd = "openssl req -x509 -newkey rsa:2048 -keyout " + key + " -out " + cert +
		" -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1";
	if (system(cmd.c_str()) != 0) {
		fprintf(stderr, "remote_files_test: openssl failed\n");
		return 1;
	}
	char dir_template[] = "/tmp/wraith_remote_files_XXXXXX";
	const fs::path dir = mkdtemp(dir_template);
	const fs::path src = dir / "copied", mnt = dir / "mnt", out = dir / "pasted";

	// What the host's user copies: a folder with a big file, a nested folder,
	// and a folder of many files (too many for the list's byte budget), plus
	// a loose file.
	fs::create_directories(src / "project" / "docs" / "deep");
	fs::create_directories(src / "project" / "many");
	write_file(src / "project" / "video.bin", pattern(24 << 20, 1));
	write_file(src / "project" / "docs" / "readme.md", "# readme\n");
	write_file(src / "project" / "docs" / "deep" / "note.txt", "deep inside\n");
	write_file(src / "project" / "docs" / "empty", "");
	for (int i = 0; i < 15000; i++) {
		write_file(src / "project" / "many" / ("file-with-a-longish-name-" + std::to_string(i) + ".txt"),
			"n" + std::to_string(i));
	}
	write_file(src / "loose.txt", "loose\n");

	wl_event_loop *loop = wl_event_loop_create();
	// Destroyed last, after everything with a source on it.
	struct LoopGuard {
		wl_event_loop *loop;
		~LoopGuard() { wl_event_loop_destroy(loop); }
	} loop_guard{loop};
	gdp::Transport server, client;
	wraith::FileSender sender(loop, [] { return 500u; }, [] { return true; });
	wraith::FileReceiver receiver(loop, dir.string(), [](uint64_t code) { fprintf(stderr, "protocol error %llu\n", (unsigned long long)code); },
		[](const std::string &, const std::string &) {});
	receiver.on_request = [&](std::unique_ptr<gdp::Stream> s, const gdp::session::FileRequest &r) {
		sender.serve(std::move(s), r);
	};
	receiver.on_listing = [&](std::unique_ptr<gdp::Stream> s, const gdp::session::FileListingRequest &r) {
		sender.serve_listing(std::move(s), r);
	};
	std::unique_ptr<gdp::Connection> server_conn;
	CHECK(server.listen(44371, "gdp-test/1", cert, key, [&](std::unique_ptr<gdp::Connection> c) {
		server_conn = std::move(c);
		server_conn->on_control_stream = [](gdp::Stream *) {};
		server_conn->on_input_stream = [](gdp::Stream *) {};
		server_conn->allow_streams(gdp::kFileStreamsAtOnce);
		server_conn->on_stream = [&](std::unique_ptr<gdp::Stream> s) { receiver.add_stream(std::move(s)); };
	}));
	auto conn = client.connect("127.0.0.1", 44371, "gdp-test/1");
	bool up = false;
	conn->on_state_changed = [&](gdp::ConnectionState s) { up = up || s == gdp::ConnectionState::kConnected; };

	// The client: a stream per request, as spectre opens them.
	gdp::RemoteFiles *files_ptr = nullptr;
	gdp::RemoteFiles files([&](uint64_t id, const gdp::RemoteFiles::Target &t, uint64_t offset, bool listing) {
		gdp::session::FileOpen open;
		if (listing) {
			open.mutable_listing()->set_list_id(t.list_id);
			open.mutable_listing()->set_index(t.index);
		} else {
			open.mutable_request()->set_list_id(t.list_id);
			open.mutable_request()->set_index(t.index);
			open.mutable_request()->set_offset(offset);
		}
		gdp::session::StreamOpen so;
		so.set_kind(gdp::kStreamKindFile);
		so.set_params(open.SerializeAsString());
		std::vector<uint8_t> frame;
		gdp::encode_frame(so, &frame);
		auto stream = conn->open_stream();
		stream->send(frame.data(), frame.size(), true);
		files_ptr->answer(id, std::move(stream));
	});
	files_ptr = &files;

	auto spin = [&](int timeout_ms, const std::function<bool()> &done) {
		int64_t start = now_ms();
		while (!done()) {
			struct pollfd fds[4] = {{server.notify_fd(), POLLIN, 0}, {client.notify_fd(), POLLIN, 0},
				{wl_event_loop_get_fd(loop), POLLIN, 0}, {files.notify_fd(), POLLIN, 0}};
			poll(fds, files.running() ? 4 : 3, 5);
			server.dispatch();
			client.dispatch();
			wl_event_loop_dispatch(loop, 0);
			wl_event_loop_dispatch_idle(loop);
			files.dispatch();
			files.tick((uint64_t)now_ms() * 1000);
			if (now_ms() - start > timeout_ms) {
				return false;
			}
		}
		return true;
	};
	CHECK(spin(5000, [&] { return up; }));
	conn->open_control_stream();
	conn->open_input_stream();

	std::string error;
	CHECK(files.start(mnt.string(), &error));

	// The host's copy: the list goes over (here by hand), the client mounts it.
	auto list = sender.set_list({(src / "project").string(), (src / "loose.txt").string()}, true);
	bool unlisted_many = false;
	for (const auto &e : list.files()) {
		if (e.name() == "many") {
			unlisted_many = e.unlisted();
		}
	}
	CHECK(unlisted_many); // 15000 names don't fit the budget
	std::vector<std::string> copied = files.add_list(list, true);
	CHECK(copied.size() == 2 && copied[0] == (mnt / "clip" / "1" / "project").string());
	CHECK(files.contains(copied[1]));

	// A file manager's paste, on another thread.
	std::atomic<bool> pasted{false};
	std::thread paster([&] {
		fs::create_directories(out);
		for (const std::string &p : copied) {
			std::error_code ec;
			fs::copy(p, out / fs::path(p).filename(), fs::copy_options::recursive, ec);
			CHECK(!ec);
			if (ec) {
				fprintf(stderr, "copy %s: %s\n", p.c_str(), ec.message().c_str());
			}
		}
		pasted = true;
	});
	CHECK(spin(120000, [&] { return pasted.load(); }));
	if (!pasted) {
		files.stop(); // fails whatever the paster waits on
	}
	paster.join();
	CHECK(snapshot(src) == snapshot(out));
	CHECK(files.pending_requests() == 0);
	CHECK(sender.active_transfers() == 0);

	// A new copy: the earlier list is still there to read, the new one too.
	write_file(src / "second.txt", "second copy\n");
	auto list2 = sender.set_list({(src / "second.txt").string()}, true);
	std::vector<std::string> copied2 = files.add_list(list2, true);
	std::atomic<int> step{0};
	std::string second, again;
	std::thread reader([&] {
		second = read_file(copied2[0]);
		again = read_file(mnt / "clip" / "1" / "project" / "docs" / "readme.md");
		// Cancelling part way: open, read a little, close.
		int fd = open((mnt / "clip" / "1" / "project" / "video.bin").c_str(), O_RDONLY | O_DIRECT);
		char buf[4096];
		CHECK(fd >= 0 && pread(fd, buf, sizeof(buf), 1 << 20) == (ssize_t)sizeof(buf));
		if (fd >= 0) {
			close(fd);
		}
		step = 1;
	});
	CHECK(spin(30000, [&] { return step.load() == 1; }));
	if (step != 1) {
		files.stop();
	}
	reader.join();
	CHECK(second == "second copy\n");
	CHECK(again == "# readme\n");
	CHECK(spin(5000, [&] { return files.pending_requests() == 0 && sender.active_transfers() == 0; }));

	// A host from before file-clipboard: its list can't say what is in a
	// folder, so the folder is left out rather than mounted empty.
	auto flat = sender.set_list({(src / "project").string(), (src / "loose.txt").string()}, false);
	CHECK(flat.files_size() == 2);
	std::vector<std::string> copied3 = files.add_list(flat, false);
	CHECK(copied3.size() == 1 && fs::path(copied3[0]).filename() == "loose.txt");

	files.stop();
	CHECK(!fs::exists(mnt));
	conn.reset();
	server_conn.reset();
	fs::remove_all(dir);
	unlink(cert.c_str());
	unlink(key.c_str());
	if (g_failures) {
		fprintf(stderr, "remote_files_test: %d check(s) failed\n", g_failures.load());
		return 1;
	}
	printf("remote_files_test: all passed\n");
	return 0;
}
