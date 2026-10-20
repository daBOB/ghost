// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// Smart cards (gdp-spec.md §8.8, docs/adr/0017): the "smartcard"
// capability, its limits, and the client's policy on the command APDUs a
// host sends a forwarded card.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace gdp {

inline constexpr const char *kCapabilitySmartcard = "smartcard";

// SmartcardReaderAdded.reader_index is 0 or 1.
inline constexpr uint32_t kMaxSmartcardReaders = 2;
// SmartcardReaderAdded.name, at most.
inline constexpr size_t kMaxSmartcardReaderName = 128;
// An ATR is at most 33 bytes (ISO/IEC 7816-3).
inline constexpr size_t kMaxAtr = 33;
// A command APDU: a 4-byte header at least; at most an extended case 4
// (header, 3-byte Lc, 65535 bytes of data, 2-byte Le).
inline constexpr size_t kMinApdu = 4;
inline constexpr size_t kMaxApdu = 65544;
// A response APDU: the status word, after up to 65536 bytes of data.
inline constexpr size_t kMinCardResponse = 2;
inline constexpr size_t kMaxCardResponse = 65538;

// What the client answers in the card's place for a command it refuses.
inline constexpr uint16_t kSwFileNotFound = 0x6a82;          // a refused SELECT
inline constexpr uint16_t kSwSecurityNotSatisfied = 0x6982;  // any other refused command
inline constexpr uint16_t kSwWrongLength = 0x6700;           // a malformed APDU

// The applets the policy tells apart, by the AID the host selected.
enum class CardApplet {
	kNone,    // nothing selected since the card was powered up
	kPiv,     // NIST SP 800-73-4 PIV, with Yubico's extensions
	kOpenPgp, // OpenPGP card 3.4, with Yubico's extensions
	kOther,   // anything else not refused at SELECT (only with pass_unknown)
};

// A write the client passes only once its user agrees (gdp-spec.md §8.8).
struct CardConsent {
	enum Kind {
		kPivGenerateKey,      // GENERATE ASYMMETRIC KEY PAIR into `slot`
		kPivImportKey,        // Yubico IMPORT KEY into `slot`
		kPivWriteObject,      // PUT DATA: `object` names it; `slot` is set for a certificate
		kPivChangePin,        // CHANGE REFERENCE DATA on the PIN
		kPivChangePuk,        // CHANGE REFERENCE DATA on the PUK
		kPivUnblockPin,       // RESET RETRY COUNTER: a new PIN by the PUK
		kPivSetManagementKey, // Yubico SET MANAGEMENT KEY
		kPivSetPinRetries,    // Yubico SET PIN RETRIES, which resets the PIN and PUK
		kPivMoveKey,          // Yubico MOVE KEY from `slot` to `to_slot`
		kPivDeleteKey,        // Yubico MOVE KEY from `slot` to nowhere
		kPivReset,            // Yubico RESET: every PIV key and certificate
		kPgpGenerateKey,      // GENERATE ASYMMETRIC KEY PAIR (P1 80) for `slot`
		kPgpImportKey,        // PUT DATA (odd INS): a private key for `slot`
		kPgpWriteData,        // PUT DATA: `object` names it
		kPgpChangePin,        // CHANGE REFERENCE DATA on PW1, the user PIN
		kPgpChangeAdminPin,   // CHANGE REFERENCE DATA on PW3, the admin PIN
		kPgpUnblockPin,       // RESET RETRY COUNTER: a new user PIN
		kPgpSetPinRetries,    // Yubico SET PIN RETRIES
		kPgpAttest,           // Yubico GET ATTESTATION: replaces `slot`'s certificate
		kPgpTerminate,        // TERMINATE DF: every OpenPGP key, and the PINs reset
	};
	Kind kind = kPivReset;
	std::string slot;    // "9A (authentication)", "signature", ...
	std::string to_slot; // kPivMoveKey
	std::string object;  // kPivWriteObject, kPgpWriteData: "the card's name and ID (CHUID)"
};

// What the client's prompt says for `consent` on the card in the reader
// named `card_name`; `what` is the same in a few words, for a refusal's
// notice ("generate a new key in slot 9A (authentication)").
struct CardConsentText {
	std::string title;
	std::string body;
	std::string allow_label;
	std::string deny_label;
	std::string what;
};
CardConsentText describe_card_consent(const CardConsent &consent, const std::string &card_name);

// What the client does with one command APDU the host sent.
struct CardVerdict {
	enum Action {
		kPass,   // transmit it to the card
		kRefuse, // answer `status` in the card's place
		kAsk,    // transmit it only if the user agrees to `consent`; else answer kSwSecurityNotSatisfied
	};
	Action action = kPass;
	uint16_t status = 0;
	// kRefuse: what the host tried, for logs ("select applet a0000005272101");
	// `notify` when it's worth telling the user too: a write refused, or a
	// command the client can't read. Middleware probing for applets a card
	// doesn't have is only logged.
	std::string refused_what;
	bool notify = false;
	CardConsent consent;
};

// The client's policy on the command APDUs a host sends a forwarded card
// (gdp-spec.md §8.8). A remote session may use the card's PIV and OpenPGP
// applets to sign, decrypt and authenticate, and write to them only with
// the client's user's consent, one command at a time. Everything the
// client can't read is refused: other applets at SELECT (a YubiKey's
// management, OATH, OTP, FIDO and HSM Auth applets among them), commands
// on logical channels other than 0, secure messaging, proprietary classes
// and unknown instructions.
//
// PC/SC transmits one APDU at a time and waits for its response, so
// nothing is held here: the caller asks its user while the host waits.
// A command chain (CLA bit 0x10) is classified by its first block; the
// rest of a chain whose first block reached the card pass.
class CardPolicy {
public:
	CardPolicy() = default;
	// `allow_maintenance` false refuses every write outright, with no
	// consent asked. `pass_unknown` passes, unfiltered, the commands for
	// applets the policy doesn't know (a national ID card, a CAC), and the
	// read commands of a card with nothing selected; the applets above
	// stay refused.
	CardPolicy(bool allow_maintenance, bool pass_unknown)
		: allow_maintenance_(allow_maintenance), pass_unknown_(pass_unknown) {}

	CardVerdict check(const uint8_t *apdu, size_t len) const;
	// A command that reached the card (check() said kPass, or the user
	// agreed), and the card's response: follows SELECT and command chains.
	void transmitted(const uint8_t *apdu, size_t len, const uint8_t *response, size_t response_len);
	// The card was powered up, reset or down: nothing is selected.
	void reset();

	CardApplet applet() const { return applet_; }
	// The AID of the SELECT that chose applet(), as the host sent it;
	// empty with nothing selected. A client sharing the card with other
	// programs selects it again before the host's next commands, so the
	// card is where the policy thinks it is.
	const std::string &selected_aid() const { return aid_; }

private:
	CardApplet applet_ = CardApplet::kNone;
	std::string aid_;
	int chain_ins_ = -1; // the INS of a chain under way, or -1
	bool allow_maintenance_ = true;
	bool pass_unknown_ = false;
};

// The applet `aid` (a SELECT's data) selects, as the policy sees it:
// kPiv, kOpenPgp, kOther for one it may pass with pass_unknown, or kNone
// for one always refused.
CardApplet applet_for_aid(const uint8_t *aid, size_t len);

// `name` without pcsc-lite's " 00 00" slot suffix, for prompts and for
// the host's reader name.
std::string plain_reader_name(const std::string &name);

} // namespace gdp
