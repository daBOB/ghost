// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "input/smartcard.hpp"

#include "gdp/smartcard.hpp"
#include "session.pb.h"
#include "log.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <map>
#include <set>

#if defined(_WIN32)
#include <windows.h>
#include <winscard.h>
#define PCSC_A(f) f##A
using ReaderState = SCARD_READERSTATEA;
#elif defined(__APPLE__)
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#define PCSC_A(f) f
using ReaderState = SCARD_READERSTATE_A;
#define SPECTRE_HAVE_PCSC 1
#elif defined(SPECTRE_HAVE_PCSC)
#include <winscard.h>
#define PCSC_A(f) f
using ReaderState = SCARD_READERSTATE;
#endif
#if defined(_WIN32)
#define SPECTRE_HAVE_PCSC 1
#endif

#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

namespace spectre {

#ifdef SPECTRE_HAVE_PCSC

namespace {

// How often the watcher looks again at the list of readers without being
// told (macOS has no reader notification), and how long it waits for the
// PC/SC service to come back (Windows stops it when the last reader
// goes).
constexpr DWORD kWatchMs = 1000;
constexpr auto kServiceRetry = std::chrono::seconds(2);

#if defined(__APPLE__)
constexpr bool kPnpNotification = false;
#else
constexpr bool kPnpNotification = true;
#endif
const char *const kPnpReader = "\\\\?PnP?\\Notification";

// PC/SC's return codes, compared as the 32-bit values they are: macOS
// has LONG as int32_t and the codes as unsigned literals past INT_MAX,
// pcsclite a 64-bit long holding them positive, Windows a 32-bit long.
constexpr uint32_t code(LONG rv) {
	return (uint32_t)rv;
}
template <typename Code> constexpr bool is(LONG rv, Code expected) {
	return code(rv) == (uint32_t)expected;
}

int error_for(LONG rv) {
	switch (code(rv)) {
	case (uint32_t)SCARD_E_NO_SMARTCARD:
	case (uint32_t)SCARD_W_REMOVED_CARD:
	case (uint32_t)SCARD_E_UNKNOWN_READER:
	case (uint32_t)SCARD_E_READER_UNAVAILABLE:
	case (uint32_t)SCARD_W_UNPOWERED_CARD:
	case (uint32_t)SCARD_W_UNRESPONSIVE_CARD: return gdp::session::SMARTCARD_ERROR_NO_CARD;
	case (uint32_t)SCARD_E_SHARING_VIOLATION: return gdp::session::SMARTCARD_ERROR_BUSY;
	}
	return gdp::session::SMARTCARD_ERROR_FAILED;
}

bool service_gone(LONG rv) {
	return is(rv, SCARD_E_NO_SERVICE) || is(rv, SCARD_E_SERVICE_STOPPED) || is(rv, SCARD_E_INVALID_HANDLE);
}

// Every reader the service lists, but ghost's own: a spectre inside a
// session would otherwise forward that session's readers back into it.
std::vector<std::string> list_readers(SCARDCONTEXT ctx, LONG *rv) {
	DWORD len = 0;
	*rv = PCSC_A(SCardListReaders)(ctx, nullptr, nullptr, &len);
	if (*rv != SCARD_S_SUCCESS || len == 0) {
		return {};
	}
	std::string buf(len, '\0');
	*rv = PCSC_A(SCardListReaders)(ctx, nullptr, buf.data(), &len);
	if (*rv != SCARD_S_SUCCESS) {
		return {};
	}
	std::vector<std::string> out;
	for (size_t i = 0; i < buf.size() && buf[i]; i += std::strlen(buf.c_str() + i) + 1) {
		std::string name = buf.c_str() + i;
		const std::string plain = gdp::plain_reader_name(name);
		const std::string suffix = " (ghost)";
		if (plain.size() >= suffix.size() && plain.compare(plain.size() - suffix.size(), suffix.size(), suffix) == 0) {
			continue;
		}
		out.push_back(std::move(name));
	}
	return out;
}

bool card_in(DWORD state) {
	return (state & SCARD_STATE_PRESENT) && !(state & SCARD_STATE_MUTE);
}

} // namespace

SmartcardReaders::SmartcardReaders() {
#ifndef _WIN32
	if (pipe(notify_) == 0) {
		for (int fd : notify_) {
			fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
			fcntl(fd, F_SETFD, FD_CLOEXEC);
		}
	} else {
		notify_[0] = notify_[1] = -1;
	}
#endif
}

SmartcardReaders::~SmartcardReaders() {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		stopping_ = true;
		if (watch_context_valid_) {
			SCardCancel(static_cast<SCARDCONTEXT>(watch_context_));
		}
	}
	cv_.notify_all();
	if (watcher_.joinable()) {
		watcher_.join();
	}
	if (worker_.joinable()) {
		worker_.join();
	}
#ifndef _WIN32
	for (int fd : notify_) {
		if (fd >= 0) {
			close(fd);
		}
	}
#endif
}

bool SmartcardReaders::start() {
	watcher_ = std::thread([this] { watch_loop(); });
	worker_ = std::thread([this] { work_loop(); });
	return true;
}

bool SmartcardReaders::stopping() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return stopping_;
}

void SmartcardReaders::push(Event event) {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		events_.push_back(std::move(event));
	}
#ifndef _WIN32
	if (notify_[1] >= 0) {
		char b = 1;
		(void)!write(notify_[1], &b, 1);
	}
#endif
}

std::vector<SmartcardReaders::Event> SmartcardReaders::take_events() {
#ifndef _WIN32
	if (notify_[0] >= 0) {
		char buf[64];
		while (read(notify_[0], buf, sizeof buf) > 0) {
		}
	}
#endif
	std::vector<Event> out;
	std::lock_guard<std::mutex> lock(mutex_);
	out.swap(events_);
	return out;
}

void SmartcardReaders::power(const std::string &reader, uint32_t sequence, int action) {
	Request r;
	r.kind = Request::kPower;
	r.reader = reader;
	r.sequence = sequence;
	r.action = action;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		requests_.push_back(std::move(r));
	}
	cv_.notify_all();
}

void SmartcardReaders::transmit(const std::string &reader, uint32_t sequence, std::string apdu,
	std::string reselect) {
	Request r;
	r.kind = Request::kTransmit;
	r.reader = reader;
	r.sequence = sequence;
	r.apdu = std::move(apdu);
	r.reselect = std::move(reselect);
	{
		std::lock_guard<std::mutex> lock(mutex_);
		requests_.push_back(std::move(r));
	}
	cv_.notify_all();
}

void SmartcardReaders::release(const std::string &reader) {
	Request r;
	r.kind = Request::kRelease;
	r.reader = reader;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		requests_.push_back(std::move(r));
	}
	cv_.notify_all();
}

void SmartcardReaders::watch_loop() {
	SCARDCONTEXT ctx = 0;
	bool have_ctx = false;
	struct Known {
		DWORD state = SCARD_STATE_UNAWARE;
		bool card = false;
	};
	std::map<std::string, Known> known;
	bool logged_no_service = false;
	auto drop_all = [&] {
		for (const auto &[name, k] : known) {
			Event e;
			e.kind = Event::kReaderRemoved;
			e.reader = name;
			push(std::move(e));
		}
		known.clear();
	};
	auto wait = [&](std::chrono::milliseconds d) {
		std::unique_lock<std::mutex> lock(mutex_);
		cv_.wait_for(lock, d, [&] { return stopping_; });
	};
	while (!stopping()) {
		if (!have_ctx) {
			LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx);
			if (rv != SCARD_S_SUCCESS) {
				if (!logged_no_service) {
					SLOG_INFO("spectre: smartcard: no PC/SC service here yet (0x%lx); watching for one",
						static_cast<unsigned long>(rv));
					logged_no_service = true;
				}
				wait(kServiceRetry);
				continue;
			}
			have_ctx = true;
			std::lock_guard<std::mutex> lock(mutex_);
			watch_context_ = static_cast<uintptr_t>(ctx);
			watch_context_valid_ = true;
		}
		// The list first, then the state of everything on it.
		LONG rv = SCARD_S_SUCCESS;
		std::vector<std::string> names = list_readers(ctx, &rv);
		if (service_gone(rv)) {
			drop_all();
		} else {
			std::set<std::string> now(names.begin(), names.end());
			for (auto it = known.begin(); it != known.end();) {
				if (now.count(it->first)) {
					++it;
					continue;
				}
				Event e;
				e.kind = Event::kReaderRemoved;
				e.reader = it->first;
				push(std::move(e));
				it = known.erase(it);
			}
			for (const std::string &name : names) {
				known.emplace(name, Known{});
			}
		}
		std::vector<ReaderState> states;
		std::vector<std::string> order;
		for (auto &[name, k] : known) {
			ReaderState s = {};
			s.szReader = name.c_str();
			s.dwCurrentState = k.state;
			states.push_back(s);
			order.push_back(name);
		}
		if (kPnpNotification) {
			ReaderState s = {};
			s.szReader = kPnpReader;
			s.dwCurrentState = static_cast<DWORD>(names.size()) << 16;
			states.push_back(s);
		}
		if (states.empty()) {
			wait(std::chrono::milliseconds(kWatchMs));
			continue;
		}
		rv = PCSC_A(SCardGetStatusChange)(ctx, kWatchMs, states.data(), static_cast<DWORD>(states.size()));
		if (service_gone(rv)) {
			drop_all();
			{
				std::lock_guard<std::mutex> lock(mutex_);
				watch_context_valid_ = false;
			}
			SCardReleaseContext(ctx);
			have_ctx = false;
			logged_no_service = false;
			wait(kServiceRetry);
			continue;
		}
		if (rv != SCARD_S_SUCCESS) {
			// A timeout, a cancel, or a reader that left between the list
			// and the wait: look again.
			if (!is(rv, SCARD_E_TIMEOUT) && !is(rv, SCARD_E_CANCELLED) && !is(rv, SCARD_E_UNKNOWN_READER)) {
				wait(std::chrono::milliseconds(kWatchMs));
			}
			continue;
		}
		for (size_t i = 0; i < order.size(); i++) {
			Known &k = known[order[i]];
			const DWORD state = states[i].dwEventState & ~SCARD_STATE_CHANGED;
			const bool card = card_in(state);
			const std::string atr(reinterpret_cast<const char *>(states[i].rgbAtr),
				std::min<size_t>(states[i].cbAtr, gdp::kMaxAtr));
			if (k.state == SCARD_STATE_UNAWARE) {
				Event e;
				e.kind = Event::kReaderAdded;
				e.reader = order[i];
				e.card = card && !atr.empty();
				e.atr = e.card ? atr : "";
				push(std::move(e));
			} else if (card != k.card) {
				Event e;
				e.kind = card ? Event::kCardInserted : Event::kCardRemoved;
				e.reader = order[i];
				e.atr = card ? atr : "";
				if (!card || !atr.empty()) {
					push(std::move(e));
				}
			}
			k.state = state;
			k.card = card && !atr.empty();
		}
	}
	if (have_ctx) {
		{
			std::lock_guard<std::mutex> lock(mutex_);
			watch_context_valid_ = false;
		}
		SCardReleaseContext(ctx);
	}
}

void SmartcardReaders::work_loop() {
	using Clock = std::chrono::steady_clock;
	SCARDCONTEXT ctx = 0;
	bool have_ctx = false;
	struct Open {
		SCARDHANDLE handle = 0;
		DWORD protocol = 0;
		bool shared = false;
		bool in_transaction = false;
		Clock::time_point last;
	};
	std::map<std::string, Open> open;
	auto end_transaction = [](Open &o) {
		if (o.in_transaction) {
			SCardEndTransaction(o.handle, SCARD_LEAVE_CARD);
			o.in_transaction = false;
		}
	};
	auto close_card = [&](const std::string &reader, DWORD disposition) {
		auto it = open.find(reader);
		if (it != open.end()) {
			end_transaction(it->second);
			SCardDisconnect(it->second.handle, disposition);
			open.erase(it);
			SLOG_INFO("spectre: smartcard: \"%s\" let go", reader.c_str());
		}
	};
	auto send = [](Open &o, const std::string &apdu, std::vector<uint8_t> *rx, DWORD *rx_len) {
		*rx_len = static_cast<DWORD>(rx->size());
		const SCARD_IO_REQUEST *pci = o.protocol == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0;
		return SCardTransmit(o.handle, pci, reinterpret_cast<const BYTE *>(apdu.data()),
			static_cast<DWORD>(apdu.size()), nullptr, rx->data(), rx_len);
	};
	std::vector<uint8_t> rx(gdp::kMaxCardResponse);
	for (;;) {
		Request r;
		{
			std::unique_lock<std::mutex> lock(mutex_);
			// Wake for the next request, or to end a shared card's
			// transaction once the host has gone quiet.
			auto due = Clock::time_point::max();
			for (const auto &[reader, o] : open) {
				if (o.in_transaction) {
					due = std::min(due, o.last + std::chrono::milliseconds(kBurstIdleMs));
				}
			}
			cv_.wait_until(lock, due, [&] { return stopping_ || !requests_.empty() || Clock::now() >= due; });
			if (stopping_) {
				break;
			}
			if (requests_.empty()) {
				lock.unlock();
				for (auto &[reader, o] : open) {
					if (o.in_transaction && Clock::now() >= o.last + std::chrono::milliseconds(kBurstIdleMs)) {
						end_transaction(o);
					}
				}
				continue;
			}
			r = std::move(requests_.front());
			requests_.pop_front();
		}
		if (!have_ctx) {
			have_ctx = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx) == SCARD_S_SUCCESS;
		}
		if (r.kind == Request::kRelease) {
			close_card(r.reader, SCARD_RESET_CARD);
			continue;
		}
		Event e;
		e.reader = r.reader;
		e.sequence = r.sequence;
		if (!have_ctx) {
			e.kind = r.kind == Request::kPower ? Event::kPowered : Event::kResponse;
			e.error = gdp::session::SMARTCARD_ERROR_FAILED;
			push(std::move(e));
			continue;
		}
		if (r.kind == Request::kPower) {
			e.kind = Event::kPowered;
			if (r.action == gdp::session::SMARTCARD_POWER_ACTION_DOWN) {
				auto it = open.find(r.reader);
				// Shared, the card stays powered for the other programs.
				close_card(r.reader, it != open.end() && it->second.shared ? SCARD_RESET_CARD : SCARD_UNPOWER_CARD);
				push(std::move(e));
				continue;
			}
			// Up on a powered card, or a reset: the card starts over.
			LONG rv;
			auto it = open.find(r.reader);
			if (it != open.end()) {
				Open &o = it->second;
				end_transaction(o);
				rv = SCardReconnect(o.handle, o.shared ? SCARD_SHARE_SHARED : SCARD_SHARE_EXCLUSIVE,
					SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, SCARD_RESET_CARD, &o.protocol);
				if (rv != SCARD_S_SUCCESS) {
					close_card(r.reader, SCARD_LEAVE_CARD);
				}
			} else {
				Open o;
				rv = PCSC_A(SCardConnect)(ctx, r.reader.c_str(), SCARD_SHARE_EXCLUSIVE,
					SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &o.handle, &o.protocol);
				if (is(rv, SCARD_E_SHARING_VIOLATION)) {
					rv = PCSC_A(SCardConnect)(ctx, r.reader.c_str(), SCARD_SHARE_SHARED,
						SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &o.handle, &o.protocol);
					o.shared = rv == SCARD_S_SUCCESS;
				}
				if (rv == SCARD_S_SUCCESS) {
					open[r.reader] = o;
					SLOG_INFO("spectre: smartcard: \"%s\" opened for the host (T=%d)%s", r.reader.c_str(),
						o.protocol == SCARD_PROTOCOL_T1 ? 1 : 0,
						o.shared ? ", shared with another program here: the host's commands go in transactions" : "");
				}
			}
			if (rv == SCARD_S_SUCCESS) {
				BYTE atr[64];
				DWORD atr_len = sizeof atr, state = 0, protocol = 0;
				char name[256];
				DWORD name_len = sizeof name;
				rv = PCSC_A(SCardStatus)(open[r.reader].handle, name, &name_len, &state, &protocol, atr, &atr_len);
				if (rv == SCARD_S_SUCCESS && atr_len > 0 && atr_len <= gdp::kMaxAtr) {
					e.atr.assign(reinterpret_cast<const char *>(atr), atr_len);
				} else if (rv == SCARD_S_SUCCESS) {
					rv = (LONG)SCARD_F_UNKNOWN_ERROR;
				}
			}
			if (rv != SCARD_S_SUCCESS) {
				SLOG_ERROR("spectre: smartcard: \"%s\": can't power the card up (0x%lx)", r.reader.c_str(),
					static_cast<unsigned long>(rv));
				e.error = error_for(rv);
				close_card(r.reader, SCARD_LEAVE_CARD);
			}
			push(std::move(e));
			continue;
		}
		e.kind = Event::kResponse;
		e.apdu = std::move(r.apdu);
		auto it = open.find(r.reader);
		if (it == open.end()) {
			e.error = gdp::session::SMARTCARD_ERROR_NO_CARD;
			push(std::move(e));
			continue;
		}
		Open &o = it->second;
		DWORD rx_len = 0;
		LONG rv = SCARD_S_SUCCESS;
		if (o.shared && !o.in_transaction) {
			rv = SCardBeginTransaction(o.handle);
			if (is(rv, SCARD_W_RESET_CARD)) {
				// Another program reset the card: what the host had
				// selected and verified is gone either way.
				rv = SCardReconnect(o.handle, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
					SCARD_LEAVE_CARD, &o.protocol);
				if (rv == SCARD_S_SUCCESS) {
					rv = SCardBeginTransaction(o.handle);
				}
			}
			o.in_transaction = rv == SCARD_S_SUCCESS;
			if (o.in_transaction && !r.reselect.empty()) {
				std::string select = {'\x00', '\xa4', '\x04', '\x00', static_cast<char>(r.reselect.size())};
				select += r.reselect;
				rv = send(o, select, &rx, &rx_len);
				const bool ok = rv == SCARD_S_SUCCESS && rx_len >= 2 &&
					((rx[rx_len - 2] == 0x90 && rx[rx_len - 1] == 0x00) || rx[rx_len - 2] == 0x61);
				if (!ok) {
					SLOG_ERROR("spectre: smartcard: \"%s\": can't select the host's applet again", r.reader.c_str());
					e.reselect_failed = true;
					e.response = std::string("\x69\x82", 2);
					o.last = Clock::now();
					push(std::move(e));
					continue;
				}
			}
		}
		if (rv == SCARD_S_SUCCESS) {
			rv = send(o, e.apdu, &rx, &rx_len);
		}
		o.last = Clock::now();
		if (rv == SCARD_S_SUCCESS && rx_len >= gdp::kMinCardResponse) {
			e.response.assign(reinterpret_cast<const char *>(rx.data()), rx_len);
		} else {
			// Never the APDU: it may hold a PIN.
			SLOG_ERROR("spectre: smartcard: \"%s\": transmit failed (0x%lx)", r.reader.c_str(),
				static_cast<unsigned long>(rv));
			e.error = error_for(rv == SCARD_S_SUCCESS ? (LONG)SCARD_F_UNKNOWN_ERROR : rv);
			if (e.error == gdp::session::SMARTCARD_ERROR_NO_CARD) {
				close_card(r.reader, SCARD_LEAVE_CARD);
			}
		}
		push(std::move(e));
	}
	for (auto &[reader, o] : open) {
		end_transaction(o);
		SCardDisconnect(o.handle, SCARD_RESET_CARD);
	}
	if (have_ctx) {
		SCardReleaseContext(ctx);
	}
}

#else // no PC/SC in this build

SmartcardReaders::SmartcardReaders() = default;
SmartcardReaders::~SmartcardReaders() = default;
bool SmartcardReaders::start() {
	SLOG_ERROR("spectre: this build has no PC/SC, so smart cards aren't forwarded (apt install libpcsclite-dev)");
	return false;
}
void SmartcardReaders::power(const std::string &, uint32_t, int) {}
void SmartcardReaders::transmit(const std::string &, uint32_t, std::string, std::string) {}
void SmartcardReaders::release(const std::string &) {}
std::vector<SmartcardReaders::Event> SmartcardReaders::take_events() {
	return {};
}
void SmartcardReaders::watch_loop() {}
void SmartcardReaders::work_loop() {}
void SmartcardReaders::push(Event) {}
bool SmartcardReaders::stopping() const {
	return true;
}

#endif

} // namespace spectre
