// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Plain-assert unit test (same convention as token_test.cpp) for
// ClipboardPipes, the clipboard backends' pipe transfers.
#include "session/clipboard_sync.hpp"

#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>

#include <poll.h>
#include <unistd.h>
#include <wayland-server-core.h>

namespace {

// A read dropped part way (the selection's owner changed under it): its fd
// closes, so the writer sees the pipe broken -- what mutter checks before
// refusing a read "in parallel" -- and it never reports. The next read is
// unaffected.
void test_cancelled_read(wl_event_loop *loop) {
	wraith::ClipboardPipes pipes(loop);
	int first[2], second[2];
	assert(pipe(first) == 0 && pipe(second) == 0);
	int reports = 0;
	std::string got;
	pipes.read(first[0], [&](std::string) { reports++; });
	assert(write(first[1], "plain", 5) == 5);
	wl_event_loop_dispatch(loop, 0);
	pipes.cancel_reads();
	struct pollfd pfd = {first[1], POLLOUT, 0};
	assert(poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLERR));
	close(first[1]);
	wl_event_loop_dispatch(loop, 0);
	assert(reports == 0);

	pipes.read(second[0], [&](std::string raw) {
		got = std::move(raw);
		reports++;
	});
	assert(write(second[1], "copied", 6) == 6);
	close(second[1]);
	for (int i = 0; i < 10 && reports == 0; i++) {
		wl_event_loop_dispatch(loop, 10);
	}
	assert(reports == 1 && got == "copied");
}

// Cancelling reads leaves a write going.
void test_cancel_keeps_writes(wl_event_loop *loop) {
	wraith::ClipboardPipes pipes(loop);
	int fds[2];
	assert(pipe(fds) == 0);
	bool written = false;
	pipes.write(fds[1], "pasted", [&](bool ok) { written = ok; });
	pipes.cancel_reads();
	for (int i = 0; i < 10 && !written; i++) {
		wl_event_loop_dispatch(loop, 10);
	}
	assert(written);
	char buf[16] = {};
	assert(read(fds[0], buf, sizeof(buf)) == 6 && std::string(buf) == "pasted");
	close(fds[0]);
}

} // namespace

int main() {
	wl_event_loop *loop = wl_event_loop_create();
	test_cancelled_read(loop);
	test_cancel_keeps_writes(loop);
	wl_event_loop_destroy(loop);
	printf("clipboard_pipes_test: all passed\n");
	return 0;
}
