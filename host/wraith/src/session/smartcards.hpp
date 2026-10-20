// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Smart cards (gdp-spec.md §8.8, docs/adr/0017): a client's PC/SC readers
// presented in the session as readers of the session's own pcscd
// (session/pcscd.hpp), which loads ghost's reader driver
// (host/ifd-ghost) for each. Every reader has a Unix socket here, the
// driver's DEVICENAME, and a line in pcscd's reader configuration naming
// it as the client does, " (ghost)" added: ykman, for one, knows a
// YubiKey by its reader's name.
//
// The driver's requests (host/ifd-ghost/ghost_ifd.h) are answered here:
// presence from what the client last said, so pcscd's polling never
// crosses the network; power and APDUs by relaying them to the client
// (SmartcardPower, SmartcardTransmit) and its answer back. Only what the
// client passes reaches the card: the policy is the client's.
//
// A reader's configuration line outlives the client that forwarded it,
// with no card in it, while pcscd runs: changing the lines means
// restarting pcscd under the session's programs, which a client coming
// back with the same readers then doesn't need.
#pragma once

#include "gdp/smartcard.hpp"
#include "util/event_source.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

struct wl_event_loop;

namespace gdp::session {
class HostInputEnvelope;
class SmartcardReaderAdded;
class SmartcardCardInserted;
class SmartcardPowered;
class SmartcardResponse;
} // namespace gdp::session

namespace wraith {

class PcscDaemon;

class Smartcards {
public:
	using Send = std::function<void(const gdp::session::HostInputEnvelope &)>;

	struct Paths {
		std::string dir;    // the sockets and configuration; made 0700
		std::string pcscd;  // pcscd's path
		std::string driver; // libifd-ghost.so's path
	};
	// Where this host keeps them: $XDG_RUNTIME_DIR/ghost/smartcard, pcscd
	// as installed, the driver in lib/ghost/pcsc beside wraith's bin/ (or
	// where wraith was built to install it), and /run/pcscd, which pcscd
	// needs and can't make as the user. False if any is missing: the
	// session then doesn't offer "smartcard".
	static bool installed(Paths *paths);
	// The socket the session's PC/SC programs use (PCSCLITE_CSOCK_NAME).
	static std::string client_socket(const std::string &dir);
	// Puts PCSCLITE_CSOCK_NAME in the user manager's environment too, for
	// what systemd starts rather than the desktop (gpg-agent, so scdaemon,
	// is socket-activated): only in a real session, where the user manager
	// is the session's. The destructor takes it back, and so does
	// `wraith --session-ended` (withdraw_environment()), which
	// wraith.service runs however wraith stopped; either only if the value
	// is still this session's.
	void publish_environment();
	static void withdraw_environment();

	Smartcards(Paths paths, struct wl_event_loop *loop, Send send);
	~Smartcards();
	Smartcards(const Smartcards &) = delete;
	Smartcards &operator=(const Smartcards &) = delete;

	// Makes the directory, clears what a previous wraith left there, and
	// binds every socket. False, with `*error`, if it couldn't.
	bool start(std::string *error);

	void reader_added(const gdp::session::SmartcardReaderAdded &added);
	void reader_removed(uint32_t index);
	void card_inserted(const gdp::session::SmartcardCardInserted &inserted);
	void card_removed(uint32_t index);
	void powered(const gdp::session::SmartcardPowered &powered);
	void response(const gdp::session::SmartcardResponse &response);
	// The client went away: its readers are empty.
	void remove_all();

	bool present(uint32_t index) const;

private:
	struct Slot {
		Smartcards *owner = nullptr;
		uint32_t index = 0;
		std::string socket_path;
		std::string config_path;
		int listen_fd = -1;
		EventSource listen_source;
		int conn_fd = -1; // the driver, inside pcscd
		EventSource conn_source;
		std::string in;   // the driver's request so far
		bool attached = false;
		std::string name;     // as the configuration line has it, or empty for none
		bool card = false;
		std::string atr;
		// The request the client is answering, if any.
		bool pending = false;
		uint8_t pending_op = 0;
		uint32_t sequence = 0;
	};

	static int on_accept(int fd, uint32_t mask, void *data);
	static int on_request(int fd, uint32_t mask, void *data);
	void read_requests(Slot &slot);
	void handle_request(Slot &slot, uint8_t op, const std::string &payload);
	void reply(Slot &slot, uint8_t status, const std::string &payload = "");
	void fail_pending(Slot &slot, uint8_t status);
	void close_conn(Slot &slot);
	bool write_config(Slot &slot, const std::string &name);
	void remove_config(Slot &slot);
	void reject(uint32_t index, const std::string &reason);

	Paths paths_;
	bool published_ = false;
	struct wl_event_loop *loop_;
	Send send_;
	std::unique_ptr<PcscDaemon> pcscd_;
	Slot slots_[gdp::kMaxSmartcardReaders];
};

} // namespace wraith
