// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// HostFileReads against a stand-in for the host's streams: replies in
// pieces, a host that ignores ranges, refusals, timeouts, cancels, credit
// given back only as bytes are taken, and close() waking a reader blocked
// on another thread. Plain assert(), as in libgdp/tests.
#include "net/host_file_reads.hpp"

#include "gdp/framing.hpp"

#undef NDEBUG
#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

using spectre::HostFileReads;

namespace {

struct FakeChannel : HostFileReads::Channel {
	size_t *consumed;
	bool *cancelled;
	FakeChannel(size_t *c, bool *x) : consumed(c), cancelled(x) {}
	void consume(size_t n) override { *consumed += n; }
	void cancel() override { *cancelled = true; }
};

struct Asked {
	uint64_t id;
	HostFileReads::Target target;
	uint64_t offset;
	bool listing;
};

struct Rig {
	uint64_t now = 1000000;
	std::vector<Asked> asked;
	HostFileReads reads{[this](uint64_t id, const HostFileReads::Target &t, uint64_t offset,
							bool listing) { asked.push_back({id, t, offset, listing}); },
		[this] { return now; }};
	size_t consumed = 0;
	bool cancelled = false;

	uint64_t answer_last() {
		uint64_t id = asked.back().id;
		reads.answer(id, std::make_unique<FakeChannel>(&consumed, &cancelled));
		return id;
	}
};

std::vector<uint8_t> frame(const gdp::session::FileReply &reply) {
	std::vector<uint8_t> out;
	gdp::encode_frame(reply, &out);
	return out;
}

std::vector<uint8_t> sending(uint64_t offset, uint64_t size) {
	gdp::session::FileReply reply;
	reply.mutable_sending()->set_name("f");
	reply.mutable_sending()->set_offset(offset);
	reply.mutable_sending()->set_size(size);
	return frame(reply);
}

std::string read_all(HostFileReads::Read &r, int64_t *last) {
	std::string out;
	uint8_t buf[4];
	for (;;) {
		int64_t n = r.read(buf, sizeof buf, 0);
		if (n <= 0) {
			*last = n;
			return out;
		}
		out.append(reinterpret_cast<char *>(buf), static_cast<size_t>(n));
	}
}

void test_file_in_pieces() {
	Rig rig;
	auto r = rig.reads.post({7, 3}, 0);
	assert(rig.asked.empty()); // nothing until the main thread's pass
	rig.reads.dispatch();
	assert(rig.asked.size() == 1 && rig.asked[0].target.list_id == 7 && rig.asked[0].target.index == 3);
	assert(!rig.asked[0].listing && rig.asked[0].offset == 0);
	uint64_t id = rig.answer_last();

	std::vector<uint8_t> head = sending(0, 10);
	std::string body = "0123456789";
	// The reply frame split, its end arriving with the first bytes.
	rig.reads.data(id, head.data(), 2);
	int64_t last = 99;
	assert(read_all(*r, &last).empty() && last == -1); // nothing yet: timed out
	std::vector<uint8_t> rest(head.begin() + 2, head.end());
	rest.insert(rest.end(), body.begin(), body.begin() + 4);
	rig.reads.data(id, rest.data(), rest.size());
	assert(rig.consumed == head.size()); // the frame's credit, not the bytes'
	rig.reads.data(id, reinterpret_cast<const uint8_t *>(body.data()) + 4, 6);
	assert(rig.consumed == head.size());

	uint8_t buf[3];
	assert(r->read(buf, 3, 0) == 3 && std::string(reinterpret_cast<char *>(buf), 3) == "012");
	assert(rig.consumed == head.size()); // given back on the main thread's pass
	rig.reads.dispatch();
	assert(rig.consumed == head.size() + 3);

	rig.reads.fin(id);
	assert(rig.reads.active() == 0);
	assert(read_all(*r, &last) == "3456789" && last == 0);
	assert(!rig.cancelled);
}

void test_host_ignoring_ranges() {
	Rig rig;
	auto r = rig.reads.post({1, 0}, 4);
	rig.reads.dispatch();
	assert(rig.asked[0].offset == 4);
	uint64_t id = rig.answer_last();
	std::vector<uint8_t> all = sending(0, 10);
	std::string body = "abcdefghij";
	all.insert(all.end(), body.begin(), body.end());
	rig.reads.data(id, all.data(), all.size());
	// The skipped bytes' credit goes back at once: nobody will take them.
	assert(rig.consumed == all.size() - 6);
	rig.reads.fin(id);
	int64_t last = 99;
	assert(read_all(*r, &last) == "efghij" && last == 0);
}

void test_short_and_long() {
	{
		Rig rig;
		auto r = rig.reads.post({1, 0}, 0);
		rig.reads.dispatch();
		uint64_t id = rig.answer_last();
		std::vector<uint8_t> all = sending(0, 10);
		all.push_back('x');
		all.push_back('y');
		rig.reads.data(id, all.data(), all.size());
		rig.reads.fin(id); // 2 of 10
		int64_t last = 99;
		assert(read_all(*r, &last) == "xy" && last == -1); // what came, then the error
	}
	{
		Rig rig;
		auto r = rig.reads.post({1, 0}, 0);
		rig.reads.dispatch();
		uint64_t id = rig.answer_last();
		std::vector<uint8_t> all = sending(0, 1);
		all.push_back('x');
		all.push_back('y');
		rig.reads.data(id, all.data(), all.size());
		assert(rig.reads.active() == 0);
		int64_t last = 99;
		assert(read_all(*r, &last).empty() && last == -1); // more than it said
	}
}

void test_refused() {
	Rig rig;
	auto r = rig.reads.post({1, 0}, 0);
	rig.reads.dispatch();
	uint64_t id = rig.answer_last();
	gdp::session::FileReply reply;
	reply.mutable_refused()->set_code(gdp::session::FILE_ERROR_GONE);
	std::vector<uint8_t> f = frame(reply);
	rig.reads.data(id, f.data(), f.size());
	assert(rig.reads.active() == 0);
	uint8_t b;
	assert(r->read(&b, 1, 0) == -1);

	// The requester failing at once.
	auto r2 = rig.reads.post({1, 1}, 0);
	rig.reads.dispatch();
	rig.reads.fail(rig.asked.back().id);
	assert(r2->read(&b, 1, 0) == -1);
}

void test_timeouts() {
	Rig rig;
	auto silent = rig.reads.post({1, 0}, 0);
	auto stalled = rig.reads.post({1, 1}, 0);
	auto slow_reader = rig.reads.post({1, 2}, 0);
	rig.reads.dispatch();
	uint64_t silent_id = rig.asked[0].id;
	uint64_t stalled_id = rig.asked[1].id;
	uint64_t slow_id = rig.asked[2].id;
	size_t c1 = 0, c2 = 0;
	bool x1 = false, x2 = false;
	rig.reads.answer(stalled_id, std::make_unique<FakeChannel>(&c1, &x1));
	rig.reads.answer(slow_id, std::make_unique<FakeChannel>(&c2, &x2));
	std::vector<uint8_t> f = sending(0, 100);
	rig.reads.data(stalled_id, f.data(), f.size());
	f.push_back('z');
	rig.reads.data(slow_id, f.data(), f.size());

	rig.now += gdp::kFileReplyTimeoutMs * 1000ull - 1;
	rig.reads.tick(rig.now);
	assert(rig.reads.active() == 3);
	rig.now += 1;
	rig.reads.tick(rig.now);
	// The one never answered and the one whose reader waits on nothing go;
	// the one holding a byte its reader hasn't taken stays.
	assert(rig.reads.active() == 1);
	assert(x1 && !x2);
	uint8_t b;
	assert(silent->read(&b, 1, 0) == -1);
	assert(stalled->read(&b, 1, 0) == -1);
	assert(slow_reader->read(&b, 1, 0) == 1 && b == 'z');

	// An answer for a request given up on is let go.
	size_t c3 = 0;
	bool x3 = false;
	rig.reads.answer(silent_id, std::make_unique<FakeChannel>(&c3, &x3));
	assert(x3);
}

void test_cancel() {
	Rig rig;
	auto r = rig.reads.post({1, 0}, 0);
	rig.reads.dispatch();
	rig.answer_last();
	r.reset();
	assert(rig.reads.active() == 1 && !rig.cancelled);
	rig.reads.dispatch();
	assert(rig.reads.active() == 0 && rig.cancelled);

	// Cancelled before it was asked for: never asked.
	auto r2 = rig.reads.post({1, 0}, 0);
	r2.reset();
	size_t before = rig.asked.size();
	rig.reads.dispatch();
	assert(rig.asked.size() == before && rig.reads.active() == 0);
}

void test_listing() {
	Rig rig;
	auto r = rig.reads.post_listing({5, 2});
	rig.reads.dispatch();
	assert(rig.asked[0].listing && rig.asked[0].target.index == 2);
	uint64_t id = rig.answer_last();
	std::vector<uint8_t> bytes;
	for (uint32_t first : {10u, 12u}) {
		gdp::session::FileReply reply;
		reply.mutable_listing()->set_first_index(first);
		reply.mutable_listing()->add_files()->set_name("a" + std::to_string(first));
		reply.mutable_listing()->add_files()->set_name("b" + std::to_string(first));
		std::vector<uint8_t> f = frame(reply);
		bytes.insert(bytes.end(), f.begin(), f.end());
	}
	// In pieces, across both frames.
	rig.reads.data(id, bytes.data(), 3);
	rig.reads.data(id, bytes.data() + 3, bytes.size() - 3);
	assert(rig.consumed == bytes.size()); // a listing's credit goes back at once
	std::vector<gdp::session::FileListing> frames;
	assert(!r->listing(&frames, 0)); // not finished
	rig.reads.fin(id);
	assert(r->listing(&frames, 0) && frames.size() == 2);
	assert(frames[1].first_index() == 12 && frames[1].files(1).name() == "b12");

	// FIN with no frame at all is a failure.
	auto r2 = rig.reads.post_listing({5, 3});
	rig.reads.dispatch();
	rig.reads.fin(rig.answer_last());
	assert(!r2->listing(&frames, 0));
}

void test_close() {
	Rig rig;
	auto waiting = rig.reads.post({1, 0}, 0);
	auto queued = rig.reads.post({1, 1}, 0);
	rig.reads.dispatch();
	rig.answer_last();
	auto queued_later = rig.reads.post({1, 2}, 0);
	int64_t got = 99;
	auto start = std::chrono::steady_clock::now();
	std::thread reader([&] {
		uint8_t b;
		got = waiting->read(&b, 1, 60000);
	});
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	rig.reads.close();
	reader.join();
	assert(got == -1);
	assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(10));
	assert(rig.reads.active() == 0 && rig.cancelled);
	uint8_t b;
	assert(queued->read(&b, 1, 0) == -1 && queued_later->read(&b, 1, 0) == -1);
	auto after = rig.reads.post({1, 3}, 0);
	assert(after->read(&b, 1, 0) == -1);
	size_t asked = rig.asked.size();
	rig.reads.dispatch();
	assert(rig.asked.size() == asked);
}

} // namespace

int main() {
	test_file_in_pieces();
	test_host_ignoring_ranges();
	test_short_and_long();
	test_refused();
	test_timeouts();
	test_cancel();
	test_listing();
	test_close();
	std::printf("host_file_reads_test: ok\n");
	return 0;
}
