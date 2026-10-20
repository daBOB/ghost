// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// This machine's smart card readers, forwarded to the host (gdp-spec.md
// §8.8, docs/adr/0017), through its own PC/SC service: pcsc-lite on
// Linux, PCSC.framework on macOS, WinSCard on Windows -- one API, so no
// helper on any of them.
//
// Two threads, each with a PC/SC context of its own: the watcher reports
// readers and cards coming and going; the worker performs the host's
// power and transmit requests, in order, one at a time. StreamSession
// hands it requests and drains what both report on its main thread,
// where each card's policy (gdp::CardPolicy) is: a response reaches the
// host only after the policy has seen it.
//
// A card is opened exclusively while the host has it powered: its state
// (the applet selected, a PIN verified) carries from one APDU to the
// next, and a program here interleaving its own would derail the host's.
// Desktops often have a program holding every card shared (a browser,
// say), and then the card is opened shared instead: the host's commands
// go in a PC/SC transaction, which keeps other programs off the card
// until the host has been idle for kBurstIdleMs, and each new transaction
// first selects again the applet the host last selected (`reselect`),
// since another program may have moved the card in between. The host
// powering the card down, or the reader's slot ending, resets the card,
// so nothing verified for the host outlives its use. A program here
// holding the card exclusively makes power-up fail as busy.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace spectre {

class SmartcardReaders {
public:
	struct Event {
		enum Kind { kReaderAdded, kReaderRemoved, kCardInserted, kCardRemoved, kPowered, kResponse };
		Kind kind = kReaderAdded;
		std::string reader;   // its PC/SC name
		bool card = false;    // kReaderAdded: with a card in it
		std::string atr;      // kReaderAdded with a card, kCardInserted, kPowered
		uint32_t sequence = 0;
		int error = 0;        // kPowered, kResponse: a gdp::session::SmartcardError
		std::string apdu;     // kResponse: the command it answers
		std::string response; // kResponse
		// kResponse: the card was shared and selecting the host's applet
		// again failed; `response` is the client's refusal, and nothing is
		// selected any more.
		bool reselect_failed = false;
	};
	// A transaction on a shared card ends after the host has sent nothing
	// for this long: Windows resets a card whose transaction idles for 5 s.
	static constexpr int kBurstIdleMs = 2000;

	SmartcardReaders();
	// Stops both threads; every card still open is reset.
	~SmartcardReaders();
	SmartcardReaders(const SmartcardReaders &) = delete;
	SmartcardReaders &operator=(const SmartcardReaders &) = delete;

	// Starts both threads. False if this build has no PC/SC.
	bool start();

	// For the worker. `action` is a gdp::session::SmartcardPowerAction.
	void power(const std::string &reader, uint32_t sequence, int action);
	// `reselect`: the AID the host last selected (gdp::CardPolicy::
	// selected_aid()), selected again first if the card is shared and
	// other programs may have used it since.
	void transmit(const std::string &reader, uint32_t sequence, std::string apdu, std::string reselect);
	// The reader's slot ended: its card, if open, is reset and let go.
	void release(const std::string &reader);

	// What happened since the last call, in order.
	std::vector<Event> take_events();
	// Readable while events wait (POSIX); -1 on Windows.
	int notify_fd() const { return notify_[0]; }

private:
	struct Request {
		enum Kind { kPower, kTransmit, kRelease } kind = kRelease;
		std::string reader;
		uint32_t sequence = 0;
		int action = 0;
		std::string apdu;
		std::string reselect;
	};

	void watch_loop();
	void work_loop();
	void push(Event event);
	bool stopping() const;

	mutable std::mutex mutex_;
	std::condition_variable cv_;
	bool stopping_ = false;
	std::deque<Request> requests_;
	std::vector<Event> events_;
	int notify_[2] = {-1, -1};
	// The watcher's context, for SCardCancel() at shutdown.
	uintptr_t watch_context_ = 0;
	bool watch_context_valid_ = false;
	std::thread watcher_;
	std::thread worker_;
};

} // namespace spectre
