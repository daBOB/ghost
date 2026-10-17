// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Copied files going to the client (session/file_sender.hpp, gdp-spec.md
// §7.12): a real libgdp client fetches files over loopback from a
// FileSender behind a FileReceiver, on a wl_event_loop as wraith runs
// them. Covers the list (what it leaves out), a file arriving whole, a
// range of one, refusals, earlier lists kept for a while, a file that
// shrinks while it goes, the client cancelling, and file data waiting
// while the video has a backlog. Also how the clipboard
// sink tells copied files from text (session/clipboard_sync.hpp).
#include "session/clipboard_sync.hpp"
#include "session/file_receiver.hpp"
#include "session/file_sender.hpp"

#include "gdp/file_transfer.hpp"
#include "gdp/framing.hpp"
#include "gdp/transport.hpp"
#include "session.pb.h"

#include <wayland-server-core.h>

#include <poll.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace {

int g_failures = 0;
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

struct Loop {
	wl_event_loop *loop = wl_event_loop_create();
	gdp::Transport server;
	gdp::Transport client;
	~Loop() { wl_event_loop_destroy(loop); }

	bool until(int timeout_ms, const std::function<bool()> &done) {
		int64_t start = now_ms();
		for (;;) {
			if (done()) {
				return true;
			}
			struct pollfd fds[3] = {{server.notify_fd(), POLLIN, 0}, {client.notify_fd(), POLLIN, 0},
				{wl_event_loop_get_fd(loop), POLLIN, 0}};
			poll(fds, 3, 5);
			server.dispatch();
			client.dispatch();
			wl_event_loop_dispatch(loop, 0);
			wl_event_loop_dispatch_idle(loop);
			if (now_ms() - start > timeout_ms) {
				return false;
			}
		}
	}
	void run(int ms) {
		until(ms, [] { return false; });
	}
};

void write_file(const std::string &path, const std::string &content) {
	std::ofstream(path, std::ios::binary) << content;
}

std::string pattern(size_t len, unsigned seed) {
	std::string out(len, '\0');
	for (size_t i = 0; i < len; i++) {
		out[i] = static_cast<char>((i * 31 + seed + (i >> 12)) & 0xff);
	}
	return out;
}

// One client-side fetch: the request, then the host's reply and bytes.
struct Fetch {
	std::unique_ptr<gdp::Stream> stream;
	gdp::FrameThenRawReader reader{4096};
	gdp::session::FileReply reply;
	bool replied = false;
	std::string data;
	bool fin = false;
	bool reset = false;
};

std::unique_ptr<Fetch> fetch(gdp::Connection &conn, uint64_t list_id, uint32_t index, uint64_t offset = 0,
	uint64_t length = 0) {
	auto f = std::make_unique<Fetch>();
	Fetch *p = f.get();
	p->stream = conn.open_stream();
	p->stream->on_data = [p](const uint8_t *data, size_t len) {
		p->stream->consume(len);
		if (p->reader.feed(data, len) == gdp::FrameThenRawReader::State::kFramed && !p->replied) {
			p->replied = p->reply.ParseFromString(p->reader.frame());
		}
		auto more = p->reader.take_data();
		p->data.append(reinterpret_cast<const char *>(more.data()), more.size());
	};
	p->stream->on_fin = [p] { p->fin = true; };
	p->stream->on_reset = [p](uint64_t) { p->reset = true; };
	gdp::session::FileOpen open;
	open.mutable_request()->set_list_id(list_id);
	open.mutable_request()->set_index(index);
	open.mutable_request()->set_offset(offset);
	open.mutable_request()->set_length(length);
	gdp::session::StreamOpen stream_open;
	stream_open.set_kind(gdp::kStreamKindFile);
	stream_open.set_params(open.SerializeAsString());
	std::vector<uint8_t> frame;
	gdp::encode_frame(stream_open, &frame);
	p->stream->send(frame.data(), frame.size(), true);
	return f;
}

// One client-side listing request: every FileReply frame until FIN.
struct Listing {
	std::unique_ptr<gdp::Stream> stream;
	gdp::FrameReader reader;
	std::vector<gdp::session::FileListing> frames;
	gdp::session::FileErrorCode refused = gdp::session::FILE_ERROR_UNSPECIFIED;
	bool fin = false;
};

std::unique_ptr<Listing> list_folder(gdp::Connection &conn, uint64_t list_id, uint32_t index) {
	auto l = std::make_unique<Listing>();
	Listing *p = l.get();
	p->stream = conn.open_stream();
	p->stream->on_data = [p](const uint8_t *data, size_t len) {
		p->stream->consume(len);
		gdp::session::FileReply reply;
		p->reader.feed_and_drain(data, len, &reply, [&] {
			if (reply.has_listing()) {
				p->frames.push_back(reply.listing());
			} else if (reply.has_refused()) {
				p->refused = reply.refused().code();
			}
			return true;
		});
	};
	p->stream->on_fin = [p] { p->fin = true; };
	gdp::session::FileOpen open;
	open.mutable_listing()->set_list_id(list_id);
	open.mutable_listing()->set_index(index);
	gdp::session::StreamOpen stream_open;
	stream_open.set_kind(gdp::kStreamKindFile);
	stream_open.set_params(open.SerializeAsString());
	std::vector<uint8_t> frame;
	gdp::encode_frame(stream_open, &frame);
	p->stream->send(frame.data(), frame.size(), true);
	return l;
}

// A sink whose clipboard is whatever the test says was read.
class TestSink : public wraith::ClipboardSink {
public:
	explicit TestSink(wl_event_loop *loop) : ClipboardSink(loop) {}
	void set_text(const std::string &) override {}
	void read(const std::string &mime, const std::string &raw) { note_local_payload(mime, raw); }
};

void test_clipboard_sink(wl_event_loop *loop) {
	TestSink sink(loop);
	std::vector<std::vector<std::string>> lists;
	std::vector<std::string> texts;
	sink.on_local_change = [&](const std::string &text) { texts.push_back(text); };

	CHECK(wraith::ClipboardSink::select_mime({"text/plain", "x-special/gnome-copied-files",
			  "text/uri-list"}) == "x-special/gnome-copied-files");
	CHECK(wraith::ClipboardSink::select_mime({"UTF8_STRING"}) == "UTF8_STRING");

	// Nobody listing files (a client without "file"): their paths as text.
	sink.read("x-special/gnome-copied-files", "copy\nfile:///home/u/a.txt\nfile:///home/u/b%20c.txt");
	CHECK(sink.current_files() == (std::vector<std::string>{"/home/u/a.txt", "/home/u/b c.txt"}));
	CHECK(texts == (std::vector<std::string>{"/home/u/a.txt\n/home/u/b c.txt"}));
	CHECK(sink.current_text() == "/home/u/a.txt\n/home/u/b c.txt");

	// Someone listing them: files, and no text.
	texts.clear();
	sink.on_local_files = [&](const std::vector<std::string> &paths) { lists.push_back(paths); };
	sink.read("text/uri-list", "file:///tmp/x\r\n");
	CHECK(lists.size() == 1 && lists[0] == std::vector<std::string>{"/tmp/x"});
	CHECK(texts.empty());
	// Then text: the files are gone (an empty list), the text goes.
	sink.read("text/plain", "hello");
	CHECK(lists.size() == 2 && lists[1].empty());
	CHECK(texts == std::vector<std::string>{"hello"});
	CHECK(sink.current_files().empty());
	// A list with nothing local in it is not a copy of files.
	sink.read("text/uri-list", "https://example.org/x\n");
	CHECK(lists.size() == 2 && sink.current_files().empty());
}

} // namespace

int main() {
	Loop loop;
	test_clipboard_sink(loop.loop);

	const std::string cert = "/tmp/wraith_file_sender_cert.pem";
	const std::string key = "/tmp/wraith_file_sender_key.pem";
	std::string cmd = "openssl req -x509 -newkey rsa:2048 -keyout " + key + " -out " + cert +
		" -days 1 -nodes -subj /CN=localhost >/dev/null 2>&1";
	if (system(cmd.c_str()) != 0) {
		fprintf(stderr, "file_sender_test: openssl failed\n");
		return 1;
	}
	char dir_template[] = "/tmp/wraith_file_sender_XXXXXX";
	const std::string dir = mkdtemp(dir_template);
	const std::string small = "copied on the host \xe2\x9c\x93\n";
	const std::string big = pattern(5 << 20, 3);
	write_file(dir + "/small.txt", small);
	write_file(dir + "/big.bin", big);
	write_file(dir + "/shrinks.bin", pattern(3 << 20, 5));
	write_file(dir + "/empty", "");
	std::filesystem::create_directory(dir + "/folder");

	bool video_clear = true;
	uint64_t now_us = 1'000'000; // the clock lists age by
	auto sender = std::make_unique<wraith::FileSender>(
		loop.loop, [] { return 300u; }, [&] { return video_clear; }, [&] { return now_us; });
	std::vector<uint64_t> protocol_errors;
	wraith::FileReceiver receiver(
		loop.loop, dir, [&](uint64_t code) { protocol_errors.push_back(code); },
		[](const std::string &, const std::string &) {});
	receiver.on_request = [&](std::unique_ptr<gdp::Stream> s, const gdp::session::FileRequest &r) {
		sender->serve(std::move(s), r);
	};
	receiver.on_listing = [&](std::unique_ptr<gdp::Stream> s, const gdp::session::FileListingRequest &r) {
		sender->serve_listing(std::move(s), r);
	};

	std::unique_ptr<gdp::Connection> server_conn;
	CHECK(loop.server.listen(44352, "gdp-test/1", cert, key, [&](std::unique_ptr<gdp::Connection> conn) {
		server_conn = std::move(conn);
		server_conn->allow_streams(gdp::kFileStreamsAtOnce);
		server_conn->on_stream = [&](std::unique_ptr<gdp::Stream> s) { receiver.add_stream(std::move(s)); };
	}));
	auto client = loop.client.connect("127.0.0.1", 44352, "gdp-test/1");
	bool connected = false;
	client->on_state_changed = [&](gdp::ConnectionState s) {
		connected = connected || s == gdp::ConnectionState::kConnected;
	};
	CHECK(loop.until(5000, [&] { return connected; }));
	client->open_control_stream();
	client->open_input_stream();

	// The list: in order, a folder flagged, what isn't a file or folder
	// (or isn't there, or has an unusable name) left out.
	auto list = sender->set_list({dir + "/small.txt", dir + "/big.bin", dir + "/folder", "/dev/null",
		dir + "/missing", dir + "/shrinks.bin", dir + "/empty"});
	CHECK(list.list_id() == 1);
	CHECK(list.files_size() == 5);
	CHECK(list.files(0).name() == "small.txt" && list.files(0).size() == small.size() &&
		!list.files(0).directory());
	CHECK(list.files(1).name() == "big.bin" && list.files(1).size() == big.size());
	CHECK(list.files(2).name() == "folder" && list.files(2).directory());
	CHECK(list.files(3).name() == "shrinks.bin" && list.files(4).name() == "empty");
	CHECK(list.files(0).modified_unix_ms() > 0);

	// A whole file, then a big one: name, size, bytes, FIN.
	auto a = fetch(*client, 1, 0);
	CHECK(loop.until(5000, [&] { return a->fin; }));
	CHECK(a->replied && a->reply.has_sending() && a->reply.sending().name() == "small.txt");
	CHECK(a->reply.sending().size() == small.size() && a->data == small);
	CHECK(a->reply.sending().offset() == 0 && a->reply.sending().file_size() == small.size());
	auto b = fetch(*client, 1, 1);
	CHECK(loop.until(10000, [&] { return b->fin; }));
	CHECK(b->data == big && !b->reset);

	// Ranges: from the middle; to the end; cut short at the end; at and
	// past the end (no bytes, not an error).
	auto mid = fetch(*client, 1, 1, 1000, 5000);
	auto tail = fetch(*client, 1, 1, big.size() - 100);
	auto cut = fetch(*client, 1, 1, big.size() - 100, 1000);
	auto at_end = fetch(*client, 1, 1, big.size());
	CHECK(loop.until(5000, [&] { return mid->fin && tail->fin && cut->fin && at_end->fin; }));
	CHECK(mid->reply.has_sending() && mid->reply.sending().offset() == 1000 &&
		mid->reply.sending().size() == 5000 && mid->reply.sending().file_size() == big.size());
	CHECK(mid->data == big.substr(1000, 5000));
	CHECK(tail->reply.sending().size() == 100 && tail->data == big.substr(big.size() - 100));
	CHECK(cut->reply.sending().size() == 100 && cut->data == big.substr(big.size() - 100));
	CHECK(at_end->reply.has_sending() && at_end->reply.sending().size() == 0 && at_end->data.empty());
	CHECK(at_end->reply.sending().offset() == big.size());
	auto past_end = fetch(*client, 1, 1, big.size() + 7, 10);
	CHECK(loop.until(5000, [&] { return past_end->fin; }));
	CHECK(past_end->reply.sending().size() == 0 && past_end->reply.sending().offset() == big.size());
	auto e = fetch(*client, 1, 4);
	CHECK(loop.until(5000, [&] { return e->fin; }));
	CHECK(e->reply.has_sending() && e->reply.sending().size() == 0 && e->data.empty());

	// Refused: a folder, an index past the end.
	auto folder = fetch(*client, 1, 2);
	auto past = fetch(*client, 1, 9);
	CHECK(loop.until(5000, [&] { return folder->fin && past->fin; }));
	CHECK(folder->reply.has_refused() && folder->reply.refused().code() == gdp::session::FILE_ERROR_GONE);
	CHECK(past->reply.has_refused() && past->reply.refused().code() == gdp::session::FILE_ERROR_GONE);
	// A list replaced by a newer one is still answered for a while: a
	// paste still reading survives a new copy.
	auto list2 = sender->set_list({dir + "/small.txt"});
	CHECK(list2.list_id() == 2);
	auto earlier = fetch(*client, 1, 0);
	CHECK(loop.until(5000, [&] { return earlier->fin; }));
	CHECK(earlier->reply.has_sending() && earlier->data == small);
	// A file deleted after it was listed.
	write_file(dir + "/doomed.txt", "x");
	sender->set_list({dir + "/doomed.txt"});
	unlink((dir + "/doomed.txt").c_str());
	auto doomed = fetch(*client, 3, 0);
	CHECK(loop.until(5000, [&] { return doomed->fin; }));
	CHECK(doomed->reply.has_refused() && doomed->reply.refused().code() == gdp::session::FILE_ERROR_GONE);

	// While the video has a backlog, no file bytes go; then they do.
	sender->set_list({dir + "/big.bin"});
	video_clear = false;
	auto held = fetch(*client, 4, 0);
	loop.run(200);
	CHECK(held->replied && held->data.empty());
	video_clear = true;
	CHECK(loop.until(10000, [&] { return held->fin; }));
	CHECK(held->data == big);

	// The client gives up part way: the host lets go.
	auto cancelled = fetch(*client, 4, 0);
	CHECK(loop.until(5000, [&] { return !cancelled->data.empty(); }));
	cancelled->stream->reset(0);
	CHECK(loop.until(5000, [&] { return sender->active_transfers() == 0; }));

	// A file that shrinks while it goes: reset rather than a short file.
	sender->set_list({dir + "/shrinks.bin"});
	video_clear = false; // hold it until it has been cut
	auto shrinks = fetch(*client, 5, 0);
	CHECK(loop.until(5000, [&] { return shrinks->replied; }));
	CHECK(truncate((dir + "/shrinks.bin").c_str(), 1000) == 0);
	video_clear = true;
	CHECK(loop.until(5000, [&] { return shrinks->reset || shrinks->fin; }));
	CHECK(shrinks->reset && !shrinks->fin);
	CHECK(loop.until(5000, [&] { return sender->active_transfers() == 0; }));

	// Earlier lists are kept up to kKeptLists of them: lists 1 to 5 so far,
	// and a sixth pushes the oldest out.
	CHECK(sender->set_list({dir + "/small.txt"}).list_id() == 6);
	auto dropped = fetch(*client, 1, 0);
	auto kept = fetch(*client, 2, 0);
	CHECK(loop.until(5000, [&] { return dropped->fin && kept->fin; }));
	CHECK(dropped->reply.has_refused() && dropped->reply.refused().code() == gdp::session::FILE_ERROR_GONE);
	CHECK(kept->reply.has_sending() && kept->data == small);
	// ... and for kKeptListUs after each was replaced or last read from:
	// reading keeps a list alive, the others age out.
	const uint64_t kept_us = wraith::FileSender::kKeptListUs;
	now_us += kept_us - 1;
	auto just_in_time = fetch(*client, 2, 0);
	CHECK(loop.until(5000, [&] { return just_in_time->fin; }));
	CHECK(just_in_time->reply.has_sending());
	now_us += kept_us - 1;
	auto still_read = fetch(*client, 2, 0);
	auto aged_out = fetch(*client, 3, 0);
	CHECK(loop.until(5000, [&] { return still_read->fin && aged_out->fin; }));
	CHECK(still_read->reply.has_sending() && still_read->data == small);
	CHECK(aged_out->reply.has_refused() && aged_out->reply.refused().code() == gdp::session::FILE_ERROR_GONE);
	now_us += kept_us;
	auto too_late = fetch(*client, 2, 0);
	auto latest = fetch(*client, 6, 0);
	CHECK(loop.until(5000, [&] { return too_late->fin && latest->fin; }));
	CHECK(too_late->reply.has_refused() && too_late->reply.refused().code() == gdp::session::FILE_ERROR_GONE);
	CHECK(latest->reply.has_sending() && latest->data == small); // the latest never ages

	// Past kKeptLists, the list read from least recently goes, not the
	// oldest: list 6, read just now, outlives 7.
	for (int i = 0; i < 4; i++) {
		sender->set_list({dir + "/small.txt"}); // 7 to 10
	}
	now_us += 1;
	auto refresh = fetch(*client, 6, 0);
	CHECK(loop.until(5000, [&] { return refresh->fin; }));
	CHECK(sender->set_list({dir + "/small.txt"}).list_id() == 11);
	auto oldest = fetch(*client, 6, 0);
	auto evicted = fetch(*client, 7, 0);
	CHECK(loop.until(5000, [&] { return oldest->fin && evicted->fin; }));
	CHECK(oldest->reply.has_sending());
	CHECK(evicted->reply.has_refused() && evicted->reply.refused().code() == gdp::session::FILE_ERROR_GONE);

	// file-clipboard: a copied folder with what is in it, a listing on
	// request, a file inside it fetched by index; a link inside is never
	// listed, nor followed once a listed file has been swapped for one.
	std::filesystem::create_directories(dir + "/tree/sub");
	write_file(dir + "/tree/a.txt", "in the tree");
	write_file(dir + "/tree/sub/b.txt", "deeper");
	CHECK(symlink("/etc/passwd", (dir + "/tree/link").c_str()) == 0);
	auto tree = sender->set_list({dir + "/tree"}, true);
	CHECK(tree.list_id() == 12 && tree.files_size() == 4);
	CHECK(tree.files(1).name() == "a.txt" && tree.files(1).parent() == 1);
	CHECK(tree.files(2).name() == "sub" && tree.files(2).parent() == 1 && tree.files(2).directory());
	CHECK(tree.files(3).name() == "b.txt" && tree.files(3).parent() == 3);
	auto deep = fetch(*client, 12, 3);
	auto listed = list_folder(*client, 12, 0);
	auto not_folder = list_folder(*client, 12, 1);
	CHECK(loop.until(5000, [&] { return deep->fin && listed->fin && not_folder->fin; }));
	CHECK(deep->reply.has_sending() && deep->data == "deeper");
	CHECK(listed->frames.size() == 1 && listed->frames[0].first_index() == 1 &&
		listed->frames[0].files_size() == 2 && listed->frames[0].files(1).name() == "sub");
	CHECK(not_folder->refused == gdp::session::FILE_ERROR_GONE);
	unlink((dir + "/tree/sub/b.txt").c_str());
	CHECK(symlink(dir.c_str(), (dir + "/tree/sub/b.txt").c_str()) == 0);
	auto swapped = fetch(*client, 12, 3);
	CHECK(loop.until(5000, [&] { return swapped->fin; }));
	CHECK(swapped->reply.has_refused() && swapped->reply.refused().code() == gdp::session::FILE_ERROR_READ_FAILED);

	// The window grew on a quiet link.
	CHECK(sender->window().bytes() > wraith::FileWindow::kInitial);
	CHECK(protocol_errors.empty());

	// FileWindow on its own: halves on queueing delay, once a round trip.
	wraith::FileWindow w;
	for (int i = 0; i < 100; i++)
		w.update(800, 1000 * (i + 1));
	CHECK(w.bytes() == wraith::FileWindow::kMaximum);
	w.update(60000, 1'000'000);
	CHECK(w.bytes() == wraith::FileWindow::kMaximum / 2);
	w.update(60000, 1'010'000);
	CHECK(w.bytes() == wraith::FileWindow::kMaximum / 2);
	w.update(60000, 1'070'000);
	CHECK(w.bytes() == wraith::FileWindow::kMaximum / 4);

	sender.reset();
	client.reset();
	server_conn.reset();
	std::error_code ignored;
	std::filesystem::remove_all(dir, ignored);
	unlink(cert.c_str());
	unlink(key.c_str());
	if (g_failures) {
		fprintf(stderr, "file_sender_test: %d check(s) failed\n", g_failures);
		return 1;
	}
	printf("file_sender_test: all checks passed\n");
	return 0;
}
