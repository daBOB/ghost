// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The host's half of smart card forwarding, end to end without a card: a
// real pcscd started by session/pcscd.hpp, loading the built reader
// driver, relaying through session/smartcards.hpp to a fake client that
// answers like a card, and a PC/SC program on top through libpcsclite.
// Passes (skipped) where pcscd isn't installed.
#include "session/pcscd.hpp"
#include "session/smartcards.hpp"

#include "session.pb.h"

#include <wayland-server-core.h>
#include <winscard.h>

#undef NDEBUG
#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

namespace {

const std::string kAtr = "\x3b\x8c\x80\x01\x59\x75\x62\x69\x6b\x65\x79\x4e\x45\x4f\x72\x33\x58";

std::vector<std::string> list_readers(SCARDCONTEXT ctx) {
	DWORD len = 0;
	if (SCardListReaders(ctx, nullptr, nullptr, &len) != SCARD_S_SUCCESS) {
		return {};
	}
	std::string buf(len, '\0');
	if (SCardListReaders(ctx, nullptr, buf.data(), &len) != SCARD_S_SUCCESS) {
		return {};
	}
	std::vector<std::string> out;
	for (const char *p = buf.c_str(); *p; p += std::strlen(p) + 1) {
		out.emplace_back(p);
	}
	return out;
}

} // namespace

int run(const std::string &pcscd, const std::string &root) {
	const std::string dir = root + "/ghost/smartcard";
	wraith::Smartcards::Paths paths{dir, pcscd, IFD_GHOST_TEST_DRIVER};

	struct wl_event_loop *loop = wl_event_loop_create();
	// The fake client: answers on the next loop iteration, as one would
	// from across the network. `deny_puts` answers PUT DATA as a client
	// whose user said no.
	std::deque<std::function<void()>> answers;
	std::atomic<int> transmits{0};
	wraith::Smartcards *cards_ptr = nullptr;
	auto send = [&](const gdp::session::HostInputEnvelope &env) {
		if (env.has_smartcard_power()) {
			gdp::session::SmartcardPowered p;
			p.set_reader_index(env.smartcard_power().reader_index());
			p.set_sequence(env.smartcard_power().sequence());
			if (env.smartcard_power().action() != gdp::session::SMARTCARD_POWER_ACTION_DOWN) {
				p.set_atr(kAtr);
			}
			answers.push_back([&cards_ptr, p] { cards_ptr->powered(p); });
		} else if (env.has_smartcard_transmit()) {
			transmits++;
			gdp::session::SmartcardResponse r;
			r.set_reader_index(env.smartcard_transmit().reader_index());
			r.set_sequence(env.smartcard_transmit().sequence());
			const std::string &apdu = env.smartcard_transmit().apdu();
			// The card's "version", or 69 82 for a write.
			r.set_response(apdu[1] == '\xdb' ? std::string("\x69\x82", 2) : std::string("\x05\x07\x04\x90\x00", 5));
			answers.push_back([&cards_ptr, r] { cards_ptr->response(r); });
		}
	};
	wraith::Smartcards cards(paths, loop, send);
	cards_ptr = &cards;
	std::string error;
	bool started = cards.start(&error);
	if (!started) {
		std::fprintf(stderr, "start: %s\n", error.c_str());
	}
	assert(started);
	struct stat st;
	assert(stat(dir.c_str(), &st) == 0 && (st.st_mode & 0777) == 0700);

	gdp::session::SmartcardReaderAdded added;
	added.set_reader_index(0);
	added.set_name("Yubico YubiKey OTP+FIDO+CCID 00 00");
	added.set_card_present(true);
	added.set_atr(kAtr);
	cards.reader_added(added);

	setenv("PCSCLITE_CSOCK_NAME", wraith::Smartcards::client_socket(dir).c_str(), 1);
	std::atomic<int> stage{0};
	std::atomic<bool> done{false};
	std::string failure;
	std::thread app([&] {
		auto fail = [&](const std::string &why) {
			failure = why;
			done = true;
		};
		SCARDCONTEXT ctx;
		LONG rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx);
		if (rv != SCARD_S_SUCCESS) {
			return fail("SCardEstablishContext: " + std::string(pcsc_stringify_error(rv)));
		}
		std::vector<std::string> readers = list_readers(ctx);
		if (readers.size() != 1 || readers[0] != "Yubico YubiKey OTP+FIDO+CCID (ghost) 00 00") {
			return fail("readers: " + (readers.empty() ? std::string("none") : readers[0]));
		}
		SCARDHANDLE card;
		DWORD protocol = 0;
		rv = SCardConnect(ctx, readers[0].c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &card,
			&protocol);
		if (rv != SCARD_S_SUCCESS) {
			return fail("SCardConnect: " + std::string(pcsc_stringify_error(rv)));
		}
		BYTE atr[MAX_ATR_SIZE];
		DWORD atr_len = sizeof atr;
		DWORD state, proto, name_len = 0;
		rv = SCardStatus(card, nullptr, &name_len, &state, &proto, atr, &atr_len);
		if (rv != SCARD_S_SUCCESS || std::string(reinterpret_cast<char *>(atr), atr_len) != kAtr) {
			return fail("SCardStatus");
		}
		const BYTE version[] = {0x00, 0xfd, 0x00, 0x00, 0x00};
		BYTE rx[258];
		DWORD rx_len = sizeof rx;
		const SCARD_IO_REQUEST *pci = protocol == SCARD_PROTOCOL_T0 ? SCARD_PCI_T0 : SCARD_PCI_T1;
		rv = SCardTransmit(card, pci, version, sizeof version, nullptr, rx, &rx_len);
		if (rv != SCARD_S_SUCCESS || rx_len != 5 || rx[3] != 0x90) {
			return fail("SCardTransmit: " + std::string(pcsc_stringify_error(rv)));
		}
		const BYTE put[] = {0x00, 0xdb, 0x3f, 0xff, 0x02, 0x5c, 0x00};
		rx_len = sizeof rx;
		rv = SCardTransmit(card, pci, put, sizeof put, nullptr, rx, &rx_len);
		if (rv != SCARD_S_SUCCESS || rx_len != 2 || rx[0] != 0x69 || rx[1] != 0x82) {
			return fail("SCardTransmit (refused)");
		}
		SCardDisconnect(card, SCARD_LEAVE_CARD);
		stage = 1;
		// The card leaves: the reader stays, empty.
		while (stage != 2) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		SCARD_READERSTATE rs = {};
		rs.szReader = readers[0].c_str();
		rs.dwCurrentState = SCARD_STATE_PRESENT;
		rv = SCardGetStatusChange(ctx, 5000, &rs, 1);
		if (rv != SCARD_S_SUCCESS || !(rs.dwEventState & SCARD_STATE_EMPTY)) {
			return fail("card removal not seen");
		}
		SCardReleaseContext(ctx);
		stage = 3;
		// A different reader in the slot: pcscd is restarted and lists it.
		while (stage != 4) {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(300));
		rv = SCardEstablishContext(SCARD_SCOPE_USER, nullptr, nullptr, &ctx);
		if (rv != SCARD_S_SUCCESS) {
			return fail("SCardEstablishContext after restart: " + std::string(pcsc_stringify_error(rv)));
		}
		readers = list_readers(ctx);
		if (readers.size() != 1 || readers[0] != "Generic ?Smart? Reader (ghost) 00 00") {
			return fail("readers after restart: " + (readers.empty() ? std::string("none") : readers[0]));
		}
		SCardReleaseContext(ctx);
		done = true;
	});

	for (int i = 0; i < 2000 && !done; i++) {
		wl_event_loop_dispatch(loop, 10);
		while (!answers.empty()) {
			auto a = std::move(answers.front());
			answers.pop_front();
			a();
		}
		if (stage == 1) {
			cards.card_removed(0);
			stage = 2;
		}
		if (stage == 3) {
			cards.reader_removed(0);
			added.set_name("Generic \"Smart\" Reader");
			added.set_card_present(false);
			added.set_atr("");
			cards.reader_added(added);
			stage = 4;
		}
	}
	app.join();
	if (!failure.empty()) {
		std::fprintf(stderr, "smartcards_test: %s\n", failure.c_str());
		return 1;
	}
	assert(done);
	assert(transmits == 2);
	return 0;
}

int main() {
	std::string pcscd = wraith::PcscDaemon::find_pcscd();
	if (pcscd.empty()) {
		std::printf("smartcards_test: no pcscd, skipped\n");
		return 0;
	}
	char root[] = "/tmp/wraith_smartcards_test.XXXXXX";
	assert(mkdtemp(root));
	int rc = run(pcscd, root);
	std::filesystem::remove_all(root);
	if (rc == 0) {
		std::printf("smartcards_test: ok\n");
	}
	return rc;
}
