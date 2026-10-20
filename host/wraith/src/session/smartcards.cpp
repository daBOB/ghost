// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "session/smartcards.hpp"

#include "ghost_ifd.h"
#include "session.pb.h"
#include "session/pcscd.hpp"
#include "util/log.hpp"

#include <systemd/sd-bus.h>
#include <wayland-server-core.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <dirent.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace wraith {

namespace {

// pcscd's reader names are at most 128 bytes with its " 00 00" after
// them; " (ghost)" goes on this.
constexpr size_t kMaxBaseName = 100;

// What a FRIENDLYNAME line can hold: printable ASCII, no quotes.
std::string config_name(const std::string &client_name) {
	std::string out;
	for (char ch : gdp::plain_reader_name(client_name)) {
		auto c = static_cast<unsigned char>(ch);
		out += c >= 0x20 && c < 0x7f && c != '"' && c != '\\' ? ch : '?';
	}
	if (out.size() > kMaxBaseName) {
		out.resize(kMaxBaseName);
	}
	while (!out.empty() && out.back() == ' ') {
		out.pop_back();
	}
	return (out.empty() ? std::string("Smart card reader") : out) + " (ghost)";
}

bool make_dir(const std::string &path) {
	return mkdir(path.c_str(), 0700) == 0 || errno == EEXIST;
}

int bind_socket(const std::string &path, std::string *error) {
	struct sockaddr_un addr = {};
	addr.sun_family = AF_UNIX;
	if (path.size() >= sizeof addr.sun_path) {
		*error = "socket path too long: " + path;
		return -1;
	}
	std::memcpy(addr.sun_path, path.c_str(), path.size());
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	if (fd < 0) {
		*error = std::string("socket: ") + strerror(errno);
		return -1;
	}
	unlink(path.c_str());
	if (bind(fd, reinterpret_cast<struct sockaddr *>(&addr), sizeof addr) < 0 || listen(fd, 4) < 0) {
		*error = path + ": " + strerror(errno);
		close(fd);
		return -1;
	}
	return fd;
}

bool power_op(uint8_t op) {
	return op == GHOST_IFD_POWER_UP || op == GHOST_IFD_RESET || op == GHOST_IFD_POWER_DOWN;
}

uint8_t ifd_status(gdp::session::SmartcardError error) {
	return error == gdp::session::SMARTCARD_ERROR_NO_CARD ? GHOST_IFD_NO_CARD : GHOST_IFD_FAILED;
}

// systemd's SetEnvironment or UnsetEnvironment on the user manager; an
// assignment given to UnsetEnvironment removes the variable only if it
// still has that value.
void manager_environment(const char *method, const std::string &assignment) {
	sd_bus *bus = nullptr;
	if (sd_bus_open_user(&bus) < 0) {
		WLOG_ERROR("smartcard: no user bus, so %s isn't in the user manager's environment", assignment.c_str());
		return;
	}
	sd_bus_message *m = nullptr;
	sd_bus_error error = SD_BUS_ERROR_NULL;
	char *strv[] = {const_cast<char *>(assignment.c_str()), nullptr};
	int r = sd_bus_message_new_method_call(bus, &m, "org.freedesktop.systemd1", "/org/freedesktop/systemd1",
		"org.freedesktop.systemd1.Manager", method);
	if (r >= 0) {
		r = sd_bus_message_append_strv(m, strv);
	}
	if (r >= 0) {
		r = sd_bus_call(bus, m, 2000000, &error, nullptr);
	}
	if (r < 0) {
		WLOG_ERROR("smartcard: %s(%s): %s", method, assignment.c_str(), error.message ? error.message : strerror(-r));
	}
	sd_bus_error_free(&error);
	sd_bus_message_unref(m);
	sd_bus_flush_close_unref(bus);
}

std::string csock_assignment(const std::string &dir) {
	return "PCSCLITE_CSOCK_NAME=" + dir + "/pcscd.comm";
}

} // namespace

bool Smartcards::installed(Paths *paths) {
#ifdef GHOST_IFD_DRIVER_PATH
	const char *runtime = getenv("XDG_RUNTIME_DIR");
	if (!runtime || !*runtime) {
		return false;
	}
	paths->dir = std::string(runtime) + "/ghost/smartcard";
	paths->pcscd = PcscDaemon::find_pcscd();
	// Beside wraith's own binary, as both the install and the build tree
	// lay it out; else where wraith was built to install it.
	paths->driver = GHOST_IFD_DRIVER_PATH;
	char exe[4096];
	ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
	if (n > 0) {
		std::string dir(exe, static_cast<size_t>(n));
		dir.resize(dir.rfind('/'));
		std::string beside = dir.substr(0, dir.rfind('/')) + "/lib/ghost/pcsc/libifd-ghost.so";
		if (access(beside.c_str(), R_OK) == 0) {
			paths->driver = beside;
		}
	}
	return !paths->pcscd.empty() && access(paths->driver.c_str(), R_OK) == 0;
#else
	(void)paths;
	return false;
#endif
}

std::string Smartcards::client_socket(const std::string &dir) {
	return csock_assignment(dir).substr(std::strlen("PCSCLITE_CSOCK_NAME="));
}

Smartcards::Smartcards(Paths paths, struct wl_event_loop *loop, Send send)
	: paths_(std::move(paths)), loop_(loop), send_(std::move(send)) {
	for (uint32_t i = 0; i < gdp::kMaxSmartcardReaders; i++) {
		Slot &slot = slots_[i];
		slot.owner = this;
		slot.index = i;
		slot.socket_path = paths_.dir + "/reader-" + std::to_string(i) + ".sock";
		slot.config_path = paths_.dir + "/readers/reader-" + std::to_string(i);
	}
}

Smartcards::~Smartcards() {
	if (published_) {
		manager_environment("UnsetEnvironment", csock_assignment(paths_.dir));
	}
	// pcscd first, so it isn't reading what goes next.
	pcscd_.reset();
	for (Slot &slot : slots_) {
		close_conn(slot);
		slot.listen_source.reset();
		if (slot.listen_fd >= 0) {
			close(slot.listen_fd);
			unlink(slot.socket_path.c_str());
		}
		remove_config(slot);
	}
}

bool Smartcards::start(std::string *error) {
	const std::string parent = paths_.dir.substr(0, paths_.dir.rfind('/'));
	if (!make_dir(parent) || !make_dir(paths_.dir) || !make_dir(paths_.dir + "/readers")) {
		*error = paths_.dir + ": " + strerror(errno);
		return false;
	}
	// A wraith that died leaves its lines behind; pcscd won't start on a
	// line whose socket is missing, and these name readers nobody has.
	if (DIR *d = opendir((paths_.dir + "/readers").c_str())) {
		while (struct dirent *e = readdir(d)) {
			if (e->d_name[0] != '.') {
				unlinkat(dirfd(d), e->d_name, 0);
			}
		}
		closedir(d);
	}
	for (Slot &slot : slots_) {
		slot.listen_fd = bind_socket(slot.socket_path, error);
		if (slot.listen_fd < 0) {
			return false;
		}
		slot.listen_source.reset(wl_event_loop_add_fd(loop_, slot.listen_fd, WL_EVENT_READABLE, on_accept, &slot));
	}
	pcscd_ = std::make_unique<PcscDaemon>(paths_.pcscd, client_socket(paths_.dir), paths_.dir + "/readers", loop_);
	if (!pcscd_->listen(error)) {
		return false;
	}
	WLOG_INFO("smartcard: the session's PC/SC socket is %s", client_socket(paths_.dir).c_str());
	return true;
}

void Smartcards::publish_environment() {
	manager_environment("SetEnvironment", csock_assignment(paths_.dir));
	published_ = true;
}

void Smartcards::withdraw_environment() {
	Paths paths;
	if (installed(&paths)) {
		manager_environment("UnsetEnvironment", csock_assignment(paths.dir));
	}
}

bool Smartcards::present(uint32_t index) const {
	return index < gdp::kMaxSmartcardReaders && slots_[index].attached && slots_[index].card;
}

void Smartcards::reader_added(const gdp::session::SmartcardReaderAdded &added) {
	const uint32_t index = added.reader_index();
	if (index >= gdp::kMaxSmartcardReaders) {
		WLOG_ERROR("smartcard: client used reader slot %u, max is %u", index, gdp::kMaxSmartcardReaders - 1);
		return;
	}
	Slot &slot = slots_[index];
	if (added.name().size() > gdp::kMaxSmartcardReaderName || added.atr().size() > gdp::kMaxAtr) {
		reject(index, "name or ATR too long");
		return;
	}
	fail_pending(slot, GHOST_IFD_NO_CARD);
	const std::string name = config_name(added.name());
	if (name != slot.name) {
		if (!write_config(slot, name)) {
			reject(index, "can't write the reader configuration");
			return;
		}
		pcscd_->restart();
	}
	slot.attached = true;
	slot.card = added.card_present() && !added.atr().empty();
	slot.atr = slot.card ? added.atr() : "";
	WLOG_INFO("smartcard: reader %u is \"%s\"%s", index, name.c_str(), slot.card ? ", with a card" : "");
}

void Smartcards::reader_removed(uint32_t index) {
	if (index >= gdp::kMaxSmartcardReaders || !slots_[index].attached) {
		return;
	}
	Slot &slot = slots_[index];
	fail_pending(slot, GHOST_IFD_NO_CARD);
	slot.attached = false;
	slot.card = false;
	slot.atr.clear();
	// Left in pcscd's list, empty, while it runs (see the header).
	if (!pcscd_ || !pcscd_->running()) {
		remove_config(slot);
	}
	WLOG_INFO("smartcard: reader %u removed", index);
}

void Smartcards::card_inserted(const gdp::session::SmartcardCardInserted &inserted) {
	const uint32_t index = inserted.reader_index();
	if (index >= gdp::kMaxSmartcardReaders || !slots_[index].attached || inserted.atr().empty() ||
		inserted.atr().size() > gdp::kMaxAtr) {
		return;
	}
	slots_[index].card = true;
	slots_[index].atr = inserted.atr();
}

void Smartcards::card_removed(uint32_t index) {
	if (index >= gdp::kMaxSmartcardReaders || !slots_[index].attached) {
		return;
	}
	fail_pending(slots_[index], GHOST_IFD_NO_CARD);
	slots_[index].card = false;
	slots_[index].atr.clear();
}

void Smartcards::remove_all() {
	for (uint32_t i = 0; i < gdp::kMaxSmartcardReaders; i++) {
		reader_removed(i);
	}
}

void Smartcards::powered(const gdp::session::SmartcardPowered &p) {
	const uint32_t index = p.reader_index();
	if (index >= gdp::kMaxSmartcardReaders) {
		return;
	}
	Slot &slot = slots_[index];
	if (!slot.pending || !power_op(slot.pending_op) || p.sequence() != slot.sequence) {
		return;
	}
	slot.pending = false;
	if (p.error() != gdp::session::SMARTCARD_ERROR_NONE) {
		reply(slot, ifd_status(p.error()));
		return;
	}
	if (slot.pending_op == GHOST_IFD_POWER_DOWN) {
		reply(slot, GHOST_IFD_OK);
		return;
	}
	if (p.atr().empty() || p.atr().size() > gdp::kMaxAtr) {
		reply(slot, GHOST_IFD_FAILED);
		return;
	}
	slot.atr = p.atr();
	reply(slot, GHOST_IFD_OK, p.atr());
}

void Smartcards::response(const gdp::session::SmartcardResponse &r) {
	const uint32_t index = r.reader_index();
	if (index >= gdp::kMaxSmartcardReaders) {
		return;
	}
	Slot &slot = slots_[index];
	if (!slot.pending || slot.pending_op != GHOST_IFD_TRANSMIT || r.sequence() != slot.sequence) {
		return;
	}
	slot.pending = false;
	if (r.error() != gdp::session::SMARTCARD_ERROR_NONE) {
		reply(slot, ifd_status(r.error()));
		return;
	}
	if (r.response().size() < gdp::kMinCardResponse || r.response().size() > gdp::kMaxCardResponse) {
		reply(slot, GHOST_IFD_FAILED);
		return;
	}
	reply(slot, GHOST_IFD_OK, r.response());
}

int Smartcards::on_accept(int, uint32_t, void *data) {
	auto *slot = static_cast<Slot *>(data);
	int fd = accept4(slot->listen_fd, nullptr, nullptr, SOCK_CLOEXEC);
	if (fd < 0) {
		return 0;
	}
	// pcscd's driver connects again after a failure, or a new pcscd does.
	slot->owner->close_conn(*slot);
	slot->conn_fd = fd;
	slot->conn_source.reset(wl_event_loop_add_fd(slot->owner->loop_, fd, WL_EVENT_READABLE, on_request, slot));
	return 0;
}

int Smartcards::on_request(int, uint32_t, void *data) {
	auto *slot = static_cast<Slot *>(data);
	slot->owner->read_requests(*slot);
	return 0;
}

void Smartcards::read_requests(Slot &slot) {
	char buf[16384];
	ssize_t n = recv(slot.conn_fd, buf, sizeof buf, MSG_DONTWAIT);
	if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
		close_conn(slot);
		return;
	}
	if (n > 0) {
		slot.in.append(buf, static_cast<size_t>(n));
	}
	// One at a time: the driver waits for each reply before its next
	// request, so anything more is held until the client has answered.
	while (!slot.pending && slot.in.size() >= GHOST_IFD_HEADER) {
		const auto *h = reinterpret_cast<const uint8_t *>(slot.in.data());
		uint32_t len = h[1] | h[2] << 8 | h[3] << 16 | static_cast<uint32_t>(h[4]) << 24;
		if (len > GHOST_IFD_MAX_PAYLOAD) {
			WLOG_ERROR("smartcard: reader %u's driver sent a %u-byte request; dropping it", slot.index, len);
			close_conn(slot);
			return;
		}
		if (slot.in.size() < GHOST_IFD_HEADER + len) {
			return;
		}
		uint8_t op = h[0];
		std::string payload = slot.in.substr(GHOST_IFD_HEADER, len);
		slot.in.erase(0, GHOST_IFD_HEADER + len);
		handle_request(slot, op, payload);
		if (slot.conn_fd < 0) {
			return;
		}
	}
}

void Smartcards::handle_request(Slot &slot, uint8_t op, const std::string &payload) {
	if (op == GHOST_IFD_PRESENCE) {
		reply(slot, GHOST_IFD_OK, std::string(1, slot.attached && slot.card ? 1 : 0));
		return;
	}
	if (!slot.attached || !slot.card) {
		reply(slot, op == GHOST_IFD_POWER_DOWN ? GHOST_IFD_OK : GHOST_IFD_NO_CARD);
		return;
	}
	gdp::session::HostInputEnvelope env;
	if (power_op(op)) {
		auto *power = env.mutable_smartcard_power();
		power->set_reader_index(slot.index);
		power->set_sequence(++slot.sequence);
		power->set_action(op == GHOST_IFD_POWER_UP	  ? gdp::session::SMARTCARD_POWER_ACTION_UP
				: op == GHOST_IFD_RESET ? gdp::session::SMARTCARD_POWER_ACTION_RESET
										: gdp::session::SMARTCARD_POWER_ACTION_DOWN);
	} else if (op == GHOST_IFD_TRANSMIT && payload.size() >= gdp::kMinApdu && payload.size() <= gdp::kMaxApdu) {
		auto *transmit = env.mutable_smartcard_transmit();
		transmit->set_reader_index(slot.index);
		transmit->set_sequence(++slot.sequence);
		transmit->set_apdu(payload);
	} else {
		reply(slot, GHOST_IFD_FAILED);
		return;
	}
	slot.pending = true;
	slot.pending_op = op;
	send_(env);
}

void Smartcards::reply(Slot &slot, uint8_t status, const std::string &payload) {
	if (slot.conn_fd < 0) {
		return;
	}
	const auto n = static_cast<uint32_t>(payload.size());
	std::string out = {static_cast<char>(status), static_cast<char>(n), static_cast<char>(n >> 8),
		static_cast<char>(n >> 16), static_cast<char>(n >> 24)};
	out += payload;
	size_t sent = 0;
	while (sent < out.size()) {
		ssize_t r = send(slot.conn_fd, out.data() + sent, out.size() - sent, MSG_NOSIGNAL);
		if (r < 0 && errno == EINTR) {
			continue;
		}
		if (r < 0 && errno == EAGAIN) {
			// The driver is waiting on this reply and reads it as it comes.
			struct timespec ts = {0, 1000000};
			nanosleep(&ts, nullptr);
			continue;
		}
		if (r <= 0) {
			close_conn(slot);
			return;
		}
		sent += static_cast<size_t>(r);
	}
	// What the driver sent while the client was answering.
	if (!slot.in.empty()) {
		read_requests(slot);
	}
}

void Smartcards::fail_pending(Slot &slot, uint8_t status) {
	if (slot.pending) {
		slot.pending = false;
		reply(slot, slot.pending_op == GHOST_IFD_POWER_DOWN ? GHOST_IFD_OK : status);
	}
}

void Smartcards::close_conn(Slot &slot) {
	slot.conn_source.reset();
	if (slot.conn_fd >= 0) {
		close(slot.conn_fd);
		slot.conn_fd = -1;
	}
	slot.in.clear();
	// The client's answer, when it comes, is for nobody.
	slot.pending = false;
}

bool Smartcards::write_config(Slot &slot, const std::string &name) {
	// Hidden, so a pcscd starting now skips it.
	const std::string tmp = paths_.dir + "/readers/.reader-" + std::to_string(slot.index) + ".tmp";
	FILE *f = std::fopen(tmp.c_str(), "w");
	if (!f) {
		WLOG_ERROR("smartcard: %s: %s", tmp.c_str(), strerror(errno));
		return false;
	}
	std::fprintf(f, "FRIENDLYNAME \"%s\"\nDEVICENAME %s\nLIBPATH %s\n", name.c_str(), slot.socket_path.c_str(),
		paths_.driver.c_str());
	bool ok = std::fclose(f) == 0;
	// pcscd reads every file in the directory, so it never sees half of one.
	if (!ok || std::rename(tmp.c_str(), slot.config_path.c_str()) != 0) {
		WLOG_ERROR("smartcard: %s: %s", slot.config_path.c_str(), strerror(errno));
		unlink(tmp.c_str());
		return false;
	}
	slot.name = name;
	return true;
}

void Smartcards::remove_config(Slot &slot) {
	if (!slot.name.empty()) {
		unlink(slot.config_path.c_str());
		slot.name.clear();
	}
}

void Smartcards::reject(uint32_t index, const std::string &reason) {
	WLOG_ERROR("smartcard: reader %u refused: %s", index, reason.c_str());
	gdp::session::HostInputEnvelope env;
	auto *rejected = env.mutable_smartcard_rejected();
	rejected->set_reader_index(index);
	rejected->set_reason(reason);
	send_(env);
}

} // namespace wraith
