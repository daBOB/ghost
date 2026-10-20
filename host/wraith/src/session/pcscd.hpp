// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The session's own PC/SC daemon (gdp-spec.md §8.8, docs/adr/0017): a
// pcscd run as the session's user, which sees only the client's forwarded
// readers, never the host's. The session's programs reach it through
// PCSCLITE_CSOCK_NAME, which wraith puts in the desktop's environment.
//
// wraith holds the listening socket and starts pcscd on the first
// connection, socket-activated (pcscd honours LISTEN_FDS but not
// PCSCLITE_CSOCK_NAME for its own end); pcscd --auto-exit leaves after a
// minute unused, and the next connection starts it again. pcscd reads its
// reader configuration only as it starts, so restart() stops a running
// one when the readers change: connections made meanwhile wait in the
// socket's backlog, which outlives it. Its USB scanning is turned off by
// pointing PCSCLITE_HP_DROPDIR at a directory with no drivers, and polkit
// with --disable-polkit: the socket is in the user's runtime directory.
#pragma once

#include "util/event_source.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>

struct wl_event_loop;

namespace wraith {

class PcscDaemon {
public:
	// pcscd's path, or empty if it isn't installed.
	static std::string find_pcscd();

	// Serves `socket_path`; pcscd reads its readers from `config_dir`.
	PcscDaemon(std::string pcscd, std::string socket_path, std::string config_dir, struct wl_event_loop *loop);
	// Stops pcscd and removes the socket.
	~PcscDaemon();
	PcscDaemon(const PcscDaemon &) = delete;
	PcscDaemon &operator=(const PcscDaemon &) = delete;

	bool listen(std::string *error);
	// The reader configuration changed: a running pcscd is stopped, and
	// the next connection (or one already waiting) starts it again.
	void restart();
	bool running() const { return pid_ > 0; }

private:
	static int on_listen(int fd, uint32_t mask, void *data);
	static int on_exit(int fd, uint32_t mask, void *data);
	static int on_retry(void *data);
	void spawn();
	void reaped(int status);
	void watch_listener();

	std::string pcscd_;
	std::string socket_path_;
	std::string config_dir_;
	struct wl_event_loop *loop_;
	int listen_fd_ = -1;
	EventSource listen_source_;
	pid_t pid_ = -1;
	int pidfd_ = -1;
	EventSource pidfd_source_;
	EventSource retry_timer_;
	uint64_t started_us_ = 0;
	int quick_failures_ = 0;
};

} // namespace wraith
