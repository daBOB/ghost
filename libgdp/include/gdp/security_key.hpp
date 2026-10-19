// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// Security keys (gdp-spec.md §8.7, docs/adr/0015): the "security-key"
// capability and its limits. A key is relayed as CTAPHID packets, which
// neither end reads beyond their length.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace gdp {

inline constexpr const char *kCapabilitySecurityKey = "security-key";

// SecurityKeyConnect.key_index is 0 or 1, slots apart from the gamepads'.
inline constexpr uint32_t kMaxSecurityKeys = 2;
// SecurityKeyInput/Output.data: exactly one CTAPHID packet, no report ID.
inline constexpr size_t kSecurityKeyPacket = 64;
// SecurityKeyConnect.name, at most.
inline constexpr size_t kMaxSecurityKeyName = 128;

// The FIDO Alliance usage page and its CTAPHID usage: what a client looks
// for among its HID devices, and what the host's device reports.
inline constexpr uint16_t kFidoUsagePage = 0xf1d0;
inline constexpr uint16_t kFidoUsageCtaphid = 0x01;

// Whether `rd`, a HID report descriptor, is a security key's FIDO
// interface as gdp-spec.md §8.7 lets a client forward it: one top-level
// application collection, the FIDO page's CTAPHID usage, holding 64-byte
// input and output reports and nothing else -- no report IDs, no feature
// reports, nothing outside it. Every key in use reports some spelling of
// the host's fixed descriptor; this accepts any of them and nothing that
// would need a different one.
bool is_ctaphid_descriptor(const uint8_t *rd, size_t len);

// What a host asked a forwarded key for, as far as the user should know:
// gdp-spec.md §8.7's notice of the site a touch will approve.
struct KeyRequest {
	enum Kind {
		kRegister, // authenticatorMakeCredential: a new credential for rp_id
		kSignIn,   // authenticatorGetAssertion that needs a touch
		kSelect,   // authenticatorSelection, or a browser's "touch the key to pick it" registration
		kU2f,      // a U2F register or sign, which names its site only by a hash
	};
	Kind kind = kSignIn;
	std::string rp_id; // empty for kSelect and kU2f
};

// Watches the CTAPHID packets the host sends a key (SecurityKeyOutput)
// and recognises the requests that will wait for the user's touch,
// reassembling each channel's message from its packets. It only reads:
// the packets go to the key unchanged whatever it makes of them, and a
// message it can't parse is simply not reported.
class KeyRequestWatcher {
public:
	// One 64-byte packet. True, with `*request` set, when it completes a
	// request the user will be asked to touch the key for.
	bool feed(const uint8_t *packet, size_t len, KeyRequest *request);

private:
	struct Message {
		uint8_t cmd = 0;
		size_t total = 0;
		uint8_t next_seq = 0;
		std::vector<uint8_t> data;
	};
	bool complete(const Message &m, KeyRequest *request) const;
	std::map<uint32_t, Message> channels_;
};

} // namespace gdp
