// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "session/pcscd.hpp"

#include "gdp/clock.hpp"
#include "util/log.hpp"

#include <wayland-server-core.h>

#include <cerrno>
#include <csignal>
#include <cstring>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace wraith {

namespace {

int pidfd_open(pid_t pid) {
	return static_cast<int>(syscall(SYS_pidfd_open, pid, 0));
}

// pcscd exiting this soon after starting, unasked, is failing: it isn't
// started again for a while, so a broken install doesn't spin.
constexpr uint64_t kQuickExitUs = 2000000;
constexpr int kRetryMs = 10000;
constexpr int kStopGraceMs = 2000;

} // namespace

std::string PcscDaemon::find_pcscd() {
	for (const char *path : {"/usr/sbin/pcscd", "/usr/bin/pcscd", "/usr/local/sbin/pcscd"}) {
		if (access(path, X_OK) == 0) {
			return path;
		}
	}
	return "";
}

PcscDaemon::PcscDaemon(std::string pcscd, std::string socket_path, std::string config_dir,
	struct wl_event_loop *loop)
	: pcscd_(std::move(pcscd)), socket_path_(std::move(socket_path)), config_dir_(std::move(config_dir)),
	  loop_(loop) {}

PcscDaemon::~PcscDaemon() {
	pidfd_source_.reset();
	if (pid_ > 0) {
		kill(pid_, SIGTERM);
		bool gone = false;
		if (pidfd_ >= 0) {
			struct pollfd p = {pidfd_, POLLIN, 0};
			gone = poll(&p, 1, kStopGraceMs) > 0;
		}
		if (!gone) {
			kill(pid_, SIGKILL);
		}
		waitpid(pid_, nullptr, 0);
	}
	if (pidfd_ >= 0) {
		close(pidfd_);
	}
	listen_source_.reset();
	if (listen_fd_ >= 0) {
		close(listen_fd_);
		unlink(socket_path_.c_str());
	}
}

bool PcscDaemon::listen(std::string *error) {
	struct sockaddr_un addr = {};
	addr.sun_family = AF_UNIX;
	if (socket_path_.size() >= sizeof addr.sun_path) {
		*error = "socket path too long: " + socket_path_;
		return false;
	}
	std::memcpy(addr.sun_path, socket_path_.c_str(), socket_path_.size());
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		*error = std::string("socket: ") + strerror(errno);
		return false;
	}
	unlink(socket_path_.c_str());
	if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof addr) < 0 || ::listen(fd, 64) < 0) {
		*error = socket_path_ + ": " + strerror(errno);
		close(fd);
		return false;
	}
	listen_fd_ = fd;
	watch_listener();
	return true;
}

void PcscDaemon::watch_listener() {
	listen_source_.reset(wl_event_loop_add_fd(loop_, listen_fd_, WL_EVENT_READABLE, on_listen, this));
}

int PcscDaemon::on_listen(int, uint32_t, void *data) {
	auto *self = static_cast<PcscDaemon *>(data);
	// pcscd takes the socket from here; wraith only watches it again once
	// pcscd has gone.
	self->listen_source_.reset();
	self->spawn();
	return 0;
}

void PcscDaemon::spawn() {
	// Everything the child needs, built before fork(): only async-signal-
	// safe calls between fork() and exec in a threaded process.
	std::vector<std::string> args = {pcscd_, "--foreground", "--auto-exit", "--disable-polkit", "--config",
		config_dir_};
	std::vector<std::string> env_strings;
	for (char **e = environ; *e; e++) {
		std::string var = *e;
		if (var.rfind("LISTEN_", 0) == 0 || var.rfind("PCSCLITE_HP_DROPDIR=", 0) == 0) {
			continue;
		}
		env_strings.push_back(std::move(var));
	}
	env_strings.push_back("LISTEN_FDS=1");
	// Nothing there: no USB drivers, so no USB scanning.
	env_strings.push_back("PCSCLITE_HP_DROPDIR=" + socket_path_.substr(0, socket_path_.rfind('/')) + "/no-drivers");
	// Filled in by the child with its own pid.
	char listen_pid[32] = "LISTEN_PID=";
	std::vector<char *> argv, envp;
	for (std::string &a : args) {
		argv.push_back(a.data());
	}
	argv.push_back(nullptr);
	for (std::string &e : env_strings) {
		envp.push_back(e.data());
	}
	envp.push_back(listen_pid);
	envp.push_back(nullptr);

	pid_t pid = fork();
	if (pid < 0) {
		WLOG_ERROR("smartcard: can't start pcscd: fork: %s", strerror(errno));
		retry_timer_.reset(wl_event_loop_add_timer(loop_, on_retry, this));
		wl_event_source_timer_update(retry_timer_.get(), kRetryMs);
		return;
	}
	if (pid == 0) {
		// sd_listen_fds(3): the socket as fd 3, and LISTEN_PID our own.
		if (listen_fd_ == 3) {
			fcntl(3, F_SETFD, 0);
		} else if (dup2(listen_fd_, 3) < 0) {
			_exit(127);
		}
		char digits[24];
		int n = 0;
		for (pid_t p = getpid(); p > 0; p /= 10) {
			digits[n++] = static_cast<char>('0' + p % 10);
		}
		char *out = listen_pid + std::strlen(listen_pid);
		while (n > 0) {
			*out++ = digits[--n];
		}
		*out = '\0';
		sigset_t none;
		sigemptyset(&none);
		sigprocmask(SIG_SETMASK, &none, nullptr);
		execve(argv[0], argv.data(), envp.data());
		_exit(127);
	}
	pid_ = pid;
	started_us_ = gdp::monotonic_us();
	pidfd_ = pidfd_open(pid);
	if (pidfd_ < 0) {
		WLOG_ERROR("smartcard: pidfd_open failed; pcscd won't be restarted when it exits");
		return;
	}
	pidfd_source_.reset(wl_event_loop_add_fd(loop_, pidfd_, WL_EVENT_READABLE, on_exit, this));
	WLOG_INFO("smartcard: started pcscd (pid %d)", static_cast<int>(pid));
}

int PcscDaemon::on_exit(int, uint32_t, void *data) {
	auto *self = static_cast<PcscDaemon *>(data);
	int status = 0;
	waitpid(self->pid_, &status, 0);
	self->pidfd_source_.reset();
	close(self->pidfd_);
	self->pidfd_ = -1;
	self->pid_ = -1;
	self->reaped(status);
	return 0;
}

void PcscDaemon::reaped(int status) {
	const bool failed = !(WIFEXITED(status) && WEXITSTATUS(status) == 0) &&
		!(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
	if (failed && gdp::monotonic_us() - started_us_ < kQuickExitUs) {
		quick_failures_++;
		WLOG_ERROR("smartcard: pcscd exited at once (status %d); not starting it for %d s", status,
			kRetryMs / 1000);
		// Turn away whoever is waiting rather than leave them hanging.
		// Non-blocking only for this: pcscd shares the socket's flags.
		int flags = fcntl(listen_fd_, F_GETFL);
		fcntl(listen_fd_, F_SETFL, flags | O_NONBLOCK);
		for (int fd; (fd = accept4(listen_fd_, nullptr, nullptr, SOCK_CLOEXEC)) >= 0;) {
			close(fd);
		}
		fcntl(listen_fd_, F_SETFL, flags);
		retry_timer_.reset(wl_event_loop_add_timer(loop_, on_retry, this));
		wl_event_source_timer_update(retry_timer_.get(), kRetryMs);
		return;
	}
	quick_failures_ = 0;
	WLOG_INFO("smartcard: pcscd exited");
	watch_listener();
}

int PcscDaemon::on_retry(void *data) {
	auto *self = static_cast<PcscDaemon *>(data);
	self->retry_timer_.reset();
	self->watch_listener();
	return 0;
}

void PcscDaemon::restart() {
	if (pid_ > 0) {
		WLOG_INFO("smartcard: the readers changed; restarting pcscd");
		kill(pid_, SIGTERM);
	}
}

} // namespace wraith
