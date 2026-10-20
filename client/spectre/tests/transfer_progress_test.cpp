// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Plain-assert unit test for the words on spectre's upload card and the
// toast after it (net/transfer_progress.hpp): sizes and times, the rate,
// the card's lines and each way a batch can end.
#include "net/transfer_progress.hpp"

#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>

using namespace spectre;

namespace {

constexpr uint64_t kSec = 1000000;

void test_format() {
	assert(format_size(0) == "0 B");
	assert(format_size(999) == "999 B");
	assert(format_size(1000) == "1.0 KB");
	assert(format_size(12345) == "12.3 KB");
	assert(format_size(192000000) == "192 MB");
	assert(format_size(999700) == "1.0 MB"); // not "1000 KB"
	assert(format_size(1400000000) == "1.4 GB");
	assert(format_duration(7) == "0:07");
	assert(format_duration(750) == "12:30");
	assert(format_duration(3723) == "1:02:03");
}

void test_rate() {
	TransferRate r;
	assert(r.bytes_per_s() == 0);
	r.sample(10 * kSec, 0);
	r.sample(10 * kSec + kSec / 2, 5000000);
	assert(r.bytes_per_s() == 0); // too short a span to say
	r.sample(11 * kSec, 10000000);
	assert(r.bytes_per_s() == 10000000);
	// Old samples age out: the rate follows a slowdown.
	for (uint64_t t = 12; t <= 20; t++) {
		r.sample(t * kSec, 10000000 + (t - 11) * 1000000);
	}
	double now = r.bytes_per_s();
	assert(now > 900000 && now < 1100000);
	r.reset();
	assert(r.bytes_per_s() == 0);
}

void test_card() {
	UploadProgress p;
	p.files = 3;
	p.bytes = 400000000;
	p.done = 192000000;
	p.sent = 1;
	p.first = "a.iso";
	p.current = "report.pdf";
	ProgressSpec c = upload_card(p, 0);
	assert(c.title == "Sending 3 files to the host");
	assert(c.detail == "report.pdf and 1 more");
	assert(c.figures == "192 MB of 400 MB");
	assert(c.fraction > 0.47 && c.fraction < 0.49);
	c = upload_card(p, 11800000);
	assert(c.figures == "192 MB of 400 MB, 11.8 MB/s, 0:18 left");

	// One file, the last one going: no "and more".
	UploadProgress one;
	one.files = 1;
	one.bytes = 1000;
	one.first = one.current = "x.bin";
	c = upload_card(one, 0);
	assert(c.title == "Sending to the host" && c.detail == "x.bin");

	// A failed one drops out of the count.
	p.failed = 1;
	c = upload_card(p, 0);
	assert(c.title == "Sending 2 files to the host" && c.detail == "report.pdf");

	// Empty files only: by count.
	UploadProgress empty;
	empty.files = 2;
	empty.sent = 1;
	assert(empty.fraction() == 0.5);
}

void test_summary() {
	UploadProgress p;
	p.files = 1;
	p.sent = 1;
	p.first = "report.pdf";
	p.where = "/home/u/Downloads";
	ToastSpec t = upload_summary(p);
	assert(t.level == NoticeLevel::kSuccess && t.title == "Sent report.pdf to /home/u/Downloads");

	p.files = 3;
	p.sent = 3;
	assert(upload_summary(p).title == "Sent 3 files to /home/u/Downloads");

	p.sent = 2;
	p.failed = 1;
	t = upload_summary(p);
	assert(
		t.level == NoticeLevel::kWarning && t.title == "Sent 2 of 3 files" && t.body == "1 file wasn't sent");

	// Every one failed: each said so already.
	p.sent = 0;
	p.failed = 3;
	assert(upload_summary(p).title.empty());

	UploadProgress c;
	c.files = 4;
	c.sent = 1;
	c.cancelled = 3;
	t = upload_summary(c);
	assert(t.level == NoticeLevel::kWarning && t.title == "Cancelled sending 4 files" &&
		t.body == "Sent 1 of 4 before that");
	c.files = 1;
	c.sent = 0;
	c.cancelled = 1;
	c.first = "a.iso";
	t = upload_summary(c);
	assert(t.title == "Cancelled sending a.iso" && t.body.empty());
}

} // namespace

int main() {
	test_format();
	test_rate();
	test_card();
	test_summary();
	printf("transfer_progress_test: ok\n");
	return 0;
}
