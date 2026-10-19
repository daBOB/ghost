// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// Security keys (gdp-spec.md §8.7, docs/adr/0015): the "security-key"
// capability and its limits. A key is relayed as CTAPHID packets, which
// neither end reads beyond their length.
#pragma once

#include <array>
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

// Maintenance a host asked a forwarded key for, which the client passes
// only once its user agrees (gdp-spec.md §8.7).
struct KeyConsent {
	enum Kind {
		kReset,                 // authenticatorReset: every credential and the PIN, gone
		kSetPin,                // ClientPIN setPIN: a PIN on a key that has none
		kChangePin,             // ClientPIN changePIN
		kListCredentials,       // credential management: metadata and listing
		kDeleteCredential,      // credential management deleteCredential
		kUpdateUser,            // credential management updateUserInformation
		kListFingerprints,      // bio enrolment enumerateEnrollments
		kEnrolFingerprint,      // bio enrolment enrollBegin, then its samples
		kRemoveFingerprint,     // bio enrolment removeEnrollment
		kRenameFingerprint,     // bio enrolment setFriendlyName, outside an enrolment
		kAlwaysUv,              // authenticatorConfig toggleAlwaysUv
		kMinPinLength,          // authenticatorConfig setMinPINLength
		kEnterpriseAttestation, // authenticatorConfig enableEnterpriseAttestation
	};
	Kind kind = kReset;
	// kDeleteCredential, kUpdateUser: the credential's site and account,
	// when the key listed them earlier in the session; else empty.
	std::string rp_id;
	std::string user;
};

// What the client's prompt says for `consent` on the key named `key_name`.
struct KeyConsentText {
	std::string title;
	std::string body;
	std::string allow_label;
	std::string deny_label;
};
KeyConsentText describe_consent(const KeyConsent &consent, const std::string &key_name);

using KeyPacket = std::array<uint8_t, kSecurityKeyPacket>;

// What the client does with one packet the host sent a key.
struct KeyVerdict {
	// Packets to write to the key now, in order: a whole message, once its
	// last packet has arrived and it is allowed; nothing before that.
	std::vector<KeyPacket> to_key;
	// The client's own answer to the host, in the key's place, when the
	// message was refused or malformed.
	std::vector<KeyPacket> to_host;
	// `request` names what a touch would approve (gdp-spec.md §8.7's
	// notice), for a message passed to the key that waits for one.
	bool notice = false;
	KeyRequest request;
	// `refused_what` says what the host tried, for the user: "reset it",
	// "send it command 0x50", ...; `refused_why` why it can't, when there
	// is more to say than that it isn't passed.
	bool refused = false;
	std::string refused_what;
	std::string refused_why;
	// Maintenance the client may pass once its user agrees (gdp-spec.md
	// §8.7): the message is held on channel `held_cid` until approve() or
	// deny(), and `consent` says what it would do.
	bool ask = false;
	uint32_t held_cid = 0;
	KeyConsent consent;
	// Held requests the host gave up on (a CANCEL, or a new message on the
	// channel): their prompts are moot.
	std::vector<uint32_t> withdrawn;
};

// The client's policy on the CTAPHID packets a host sends a forwarded key
// (gdp-spec.md §8.7): a remote session may use the key to sign in, and
// maintain it only with the client's user's consent, one request at a
// time. Each channel's message is held until it is complete, then passed
// to the key whole, held for consent, or answered here as the key would
// refuse it: CTAP2_ERR_OPERATION_DENIED for a CTAP2 command the client
// can't describe (vendor commands, a vendor configuration subcommand) or
// that its user turned down, a CTAPHID error for a CTAPHID command outside
// the set. Allowed messages also yield the notice of what a touch would
// approve.
class KeyPolicy {
public:
	// A reset asks for consent only this long after the key was attached:
	// keys accept one only just after power-up and refuse it later anyway.
	static constexpr uint64_t kResetWindowUs = 10000000;
	// One approval to list passkeys (or fingerprints) covers the commands
	// that listing takes, while they keep coming at most this far apart.
	static constexpr uint64_t kListingGrantUs = 60000000;
	// One approval to enrol a fingerprint covers its samples and naming.
	static constexpr uint64_t kEnrolGrantUs = 120000000;

	KeyPolicy() = default;
	// `attached_us`: when the key was opened, on the clock feed() is given.
	// `allow_maintenance` false refuses every maintenance command outright,
	// with no consent asked.
	KeyPolicy(uint64_t attached_us, bool allow_maintenance)
		: attached_us_(attached_us), allow_maintenance_(allow_maintenance) {}

	// One 64-byte packet from the host; `*verdict` is replaced. `now_us`
	// is the clock `attached_us` was read from.
	void feed(const uint8_t *packet, size_t len, uint64_t now_us, KeyVerdict *verdict);
	// As above, with no clock: a reset is out of its window.
	void feed(const uint8_t *packet, size_t len, KeyVerdict *verdict) { feed(packet, len, 0, verdict); }

	// The user's answer to a held request (KeyVerdict::held_cid). approve()
	// passes it to the key (`to_key`); deny() refuses it (`to_host`). A
	// request no longer held (withdrawn) yields nothing.
	void approve(uint32_t cid, uint64_t now_us, KeyVerdict *verdict);
	void deny(uint32_t cid, KeyVerdict *verdict);
	bool holding() const { return !held_.empty(); }
	// CTAPHID_KEEPALIVE (status UPNEEDED) for each held request: what a key
	// sends while it waits for a touch, so the host's FIDO client waits
	// too. The caller sends them about every 100 ms while holding().
	std::vector<KeyPacket> keepalives() const;

	// One 64-byte packet the key sent the host. Only read: the replies to
	// passkey listing name each credential's site and account, which a
	// delete or rename prompt then shows.
	void observe_key(const uint8_t *packet, size_t len);

private:
	struct Message {
		uint32_t cid = 0;
		uint8_t cmd = 0;
		size_t total = 0;
		uint8_t next_seq = 0;
		std::vector<uint8_t> data;
		std::vector<KeyPacket> packets;
	};
	// A credential-management listing request passed to the key, whose
	// reply observe_key() reads.
	struct Pending {
		uint8_t sub = 0;
		std::string rp_hash;
	};
	struct Held {
		Message message;
		KeyConsent consent;
		bool listing = false; // a credential listing, read as Pending once passed
		Pending pending;
	};
	void decide(const Message &m, uint64_t now_us, KeyVerdict *verdict);
	bool notice(const Message &m, KeyRequest *request) const;
	void pass(const Message &m, KeyVerdict *verdict);
	void read_reply(uint32_t cid, const Pending &pending, const std::vector<uint8_t> &reply);

	uint64_t attached_us_ = 0;
	bool allow_maintenance_ = true;
	std::map<uint32_t, Message> channels_;
	std::map<uint32_t, Held> held_;
	uint64_t listing_until_us_ = 0;
	uint64_t enrolling_until_us_ = 0;
	// What observe_key() learnt: a listed site by its ID's hash, and a
	// listed credential's site and account by its ID.
	std::map<uint32_t, Pending> pending_;
	std::map<uint32_t, Message> replies_;
	std::map<std::string, std::string> rp_by_hash_;
	std::string listing_rp_; // the site whose credentials are being listed
	std::map<std::string, std::pair<std::string, std::string>> credentials_;
};

} // namespace gdp
