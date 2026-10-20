// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/smartcard.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>

namespace gdp {

namespace {

// The PIV applet's full AID; hosts select it by its first five bytes.
constexpr uint8_t kPivAid[] = {0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00};
constexpr size_t kPivMinAid = 5;
// The OpenPGP applet's RID and application ID; its full AID adds a
// version, manufacturer and serial, 16 bytes in all.
constexpr uint8_t kOpenPgpAid[] = {0xd2, 0x76, 0x00, 0x01, 0x24, 0x01};
constexpr size_t kOpenPgpMaxAid = 16;

// Always refused, whatever the settings, along with any AID that is a
// prefix of one of these (a card may select an applet by part of its AID).
struct Denied {
	uint8_t aid[8];
	size_t len;
};
constexpr Denied kDenied[] = {
	// Yubico's own applets: management (which turns the key's interfaces
	// off), OTP, OATH (every code that needs no touch) and HSM Auth.
	{{0xa0, 0x00, 0x00, 0x05, 0x27}, 5},
	// The FIDO applet: CTAP over CCID, past the security key policy.
	{{0xa0, 0x00, 0x00, 0x06, 0x47}, 5},
	// GlobalPlatform's issuer security domain, and the older card manager
	// AID: they install and delete applets.
	{{0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}, 8},
	{{0xa0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}, 8},
};

struct Apdu {
	uint8_t cla = 0, ins = 0, p1 = 0, p2 = 0;
	const uint8_t *data = nullptr;
	size_t data_len = 0;
};

// ISO/IEC 7816-4's four cases, short and extended.
bool parse(const uint8_t *a, size_t n, Apdu *out) {
	if (n < kMinApdu || n > kMaxApdu) {
		return false;
	}
	out->cla = a[0];
	out->ins = a[1];
	out->p1 = a[2];
	out->p2 = a[3];
	if (n <= 5) {
		return true; // case 1, or case 2 short
	}
	if (a[4] != 0) {
		size_t lc = a[4];
		if (n != 5 + lc && n != 6 + lc) {
			return false;
		}
		out->data = a + 5;
		out->data_len = lc;
		return true;
	}
	if (n == 7) {
		return true; // case 2 extended
	}
	size_t lc = static_cast<size_t>(a[5]) << 8 | a[6];
	if (lc == 0 || (n != 7 + lc && n != 9 + lc)) {
		return false;
	}
	out->data = a + 7;
	out->data_len = lc;
	return true;
}

// What CLA says, for the interindustry classes; `readable` false for
// the rest (proprietary, reserved, and 0xFF, which addresses the reader).
struct Class {
	bool readable = false;
	bool proprietary = false;
	int channel = 0;
	bool secure = false;
	bool chained = false;
};

Class decode_class(uint8_t cla) {
	Class c;
	if (cla == 0xff) {
		return c;
	}
	if (cla & 0x80) {
		c.proprietary = true;
		return c;
	}
	if ((cla & 0xe0) == 0x00) { // first interindustry: 000x xxxx
		c.readable = true;
		c.chained = cla & 0x10;
		c.secure = cla & 0x0c;
		c.channel = cla & 0x03;
	} else if ((cla & 0xc0) == 0x40) { // further interindustry: 01xx xxxx
		c.readable = true;
		c.chained = cla & 0x10;
		c.secure = cla & 0x20;
		c.channel = 4 + (cla & 0x0f);
	}
	return c; // 001x xxxx is reserved
}

std::string hex(const uint8_t *p, size_t n) {
	std::string s;
	char b[3];
	for (size_t i = 0; i < n; i++) {
		std::snprintf(b, sizeof b, "%02x", p[i]);
		s += b;
	}
	return s;
}

std::string hex_byte(uint8_t v) {
	char b[8];
	std::snprintf(b, sizeof b, "%02X", v);
	return b;
}

std::string piv_slot(uint8_t slot) {
	switch (slot) {
	case 0x9a: return "9A (authentication)";
	case 0x9c: return "9C (signature)";
	case 0x9d: return "9D (key management)";
	case 0x9e: return "9E (card authentication)";
	case 0xf9: return "F9 (attestation)";
	}
	if (slot >= 0x82 && slot <= 0x95) {
		return hex_byte(slot) + " (retired key " + std::to_string(slot - 0x81) + ")";
	}
	return hex_byte(slot);
}

// PUT DATA's object, from its tag list (5C, then the object's ID).
void piv_object(const Apdu &a, CardConsent *c) {
	uint32_t id = 0;
	if (a.data_len >= 2 && a.data[0] == 0x5c && a.data[1] >= 1 && a.data[1] <= 3 &&
		a.data_len >= 2u + a.data[1]) {
		for (uint8_t i = 0; i < a.data[1]; i++) {
			id = id << 8 | a.data[2 + i];
		}
	}
	int cert_slot = -1;
	switch (id) {
	case 0x5fc105: cert_slot = 0x9a; break;
	case 0x5fc10a: cert_slot = 0x9c; break;
	case 0x5fc10b: cert_slot = 0x9d; break;
	case 0x5fc101: cert_slot = 0x9e; break;
	case 0x5fff01: cert_slot = 0xf9; break;
	default:
		if (id >= 0x5fc10d && id <= 0x5fc120) {
			cert_slot = 0x82 + static_cast<int>(id - 0x5fc10d);
		}
	}
	if (cert_slot >= 0) {
		c->slot = piv_slot(static_cast<uint8_t>(cert_slot));
		c->object = "the certificate for slot " + c->slot;
		return;
	}
	switch (id) {
	case 0x5fc102: c->object = "the card's ID (CHUID)"; return;
	case 0x5fc107: c->object = "the card capability container"; return;
	case 0x5fc106: c->object = "the security object"; return;
	case 0x5fc109:
		c->object = "the printed information object, where a PIN-protected management key can be kept";
		return;
	case 0x5fc108: c->object = "the facial image"; return;
	case 0x5fc103: c->object = "the fingerprints"; return;
	case 0x5fc121: c->object = "the iris images"; return;
	case 0x5fc10c: c->object = "the key history"; return;
	case 0x5fff00: c->object = "the YubiKey's PIV settings"; return;
	case 0x7e: c->object = "the discovery object"; return;
	}
	char b[32];
	std::snprintf(b, sizeof b, "data object %X", id);
	c->object = b;
}

std::string pgp_key(uint8_t crt) {
	switch (crt) {
	case 0xb6: return "signature";
	case 0xb8: return "decryption";
	case 0xa4: return "authentication";
	}
	return "";
}

std::string pgp_object(uint16_t tag) {
	switch (tag) {
	case 0x005b: return "the cardholder's name";
	case 0x5f2d: return "the language preference";
	case 0x5f35: return "the salutation";
	case 0x5f50: return "the public key URL";
	case 0x005e: return "the login data";
	case 0x00c4: return "the PIN policy";
	case 0x00c1: return "the signature key's type, which erases that key";
	case 0x00c2: return "the decryption key's type, which erases that key";
	case 0x00c3: return "the authentication key's type, which erases that key";
	case 0x00c7: return "the signature key's recorded fingerprint";
	case 0x00c8: return "the decryption key's recorded fingerprint";
	case 0x00c9: return "the authentication key's recorded fingerprint";
	case 0x00ca:
	case 0x00cb:
	case 0x00cc: return "a CA fingerprint";
	case 0x00ce:
	case 0x00cf:
	case 0x00d0: return "a key's recorded creation date";
	case 0x00d3: return "the resetting code";
	case 0x00d5: return "the AES key";
	case 0x00d6: return "the signature key's touch policy";
	case 0x00d7: return "the decryption key's touch policy";
	case 0x00d8: return "the authentication key's touch policy";
	case 0x00d9: return "the attestation key's touch policy";
	case 0x7f21: return "a certificate";
	case 0x00f9: return "the PIN derivation (KDF) setting, which resets the PINs";
	}
	if (tag >= 0x0101 && tag <= 0x0104) {
		return "private data object " + std::to_string(tag - 0x0100);
	}
	char b[32];
	std::snprintf(b, sizeof b, "data object %04X", tag);
	return b;
}

// Extended header list's control reference template (OpenPGP 3.4 §4.4.3.12):
// 4D, a BER length, then B6, B8 or A4.
std::string pgp_import_key(const Apdu &a) {
	if (a.data_len < 3 || a.data[0] != 0x4d) {
		return "";
	}
	size_t i = 2;
	if (a.data[1] == 0x81) {
		i = 3;
	} else if (a.data[1] == 0x82) {
		i = 4;
	}
	return i < a.data_len ? pgp_key(a.data[i]) : "";
}

// The consent's few words, shared by the prompt and a refusal's notice.
std::string consent_what(const CardConsent &c) {
	switch (c.kind) {
	case CardConsent::kPivGenerateKey: return "generate a new PIV key in slot " + c.slot;
	case CardConsent::kPivImportKey: return "import a PIV key into slot " + c.slot;
	case CardConsent::kPivWriteObject: return "write " + c.object;
	case CardConsent::kPivChangePin: return "change the PIV PIN";
	case CardConsent::kPivChangePuk: return "change the PIV PUK";
	case CardConsent::kPivUnblockPin: return "reset the PIV PIN with the PUK";
	case CardConsent::kPivSetManagementKey: return "change the PIV management key";
	case CardConsent::kPivSetPinRetries: return "change the PIV PIN and PUK attempts";
	case CardConsent::kPivMoveKey: return "move the PIV key in slot " + c.slot + " to slot " + c.to_slot;
	case CardConsent::kPivDeleteKey: return "delete the PIV key in slot " + c.slot;
	case CardConsent::kPivReset: return "erase every PIV key and certificate";
	case CardConsent::kPgpGenerateKey: return "generate a new OpenPGP " + c.slot + " key";
	case CardConsent::kPgpImportKey: return "import an OpenPGP " + c.slot + " key";
	case CardConsent::kPgpWriteData: return "change " + c.object;
	case CardConsent::kPgpChangePin: return "change the OpenPGP PIN";
	case CardConsent::kPgpChangeAdminPin: return "change the OpenPGP admin PIN";
	case CardConsent::kPgpUnblockPin: return "reset the OpenPGP PIN";
	case CardConsent::kPgpSetPinRetries: return "change the OpenPGP PIN attempts";
	case CardConsent::kPgpAttest: return "replace the certificate for the OpenPGP " + c.slot + " key";
	case CardConsent::kPgpTerminate: return "erase every OpenPGP key";
	}
	return "change the card";
}

bool starts_with(const uint8_t *p, size_t n, const uint8_t *prefix, size_t prefix_len) {
	return n >= prefix_len && std::memcmp(p, prefix, prefix_len) == 0;
}

CardVerdict refuse(uint16_t status, std::string what, bool notify) {
	CardVerdict v;
	v.action = CardVerdict::kRefuse;
	v.status = status;
	v.refused_what = std::move(what);
	v.notify = notify;
	return v;
}

CardVerdict pass() {
	return CardVerdict{};
}

} // namespace

CardApplet applet_for_aid(const uint8_t *aid, size_t len) {
	if (len == 0) {
		return CardApplet::kNone;
	}
	for (const Denied &d : kDenied) {
		size_t n = len < d.len ? len : d.len;
		if (std::memcmp(aid, d.aid, n) == 0) {
			return CardApplet::kNone;
		}
	}
	if (len >= kPivMinAid && len <= sizeof kPivAid && std::memcmp(aid, kPivAid, len) == 0) {
		return CardApplet::kPiv;
	}
	if (len <= kOpenPgpMaxAid && starts_with(aid, len, kOpenPgpAid, sizeof kOpenPgpAid)) {
		return CardApplet::kOpenPgp;
	}
	// A prefix of either that's too short to name it could still select
	// it, partially: only the spellings above are read as theirs.
	if (std::memcmp(aid, kPivAid, len < sizeof kPivAid ? len : sizeof kPivAid) == 0 ||
		std::memcmp(aid, kOpenPgpAid, len < sizeof kOpenPgpAid ? len : sizeof kOpenPgpAid) == 0) {
		return CardApplet::kNone;
	}
	return CardApplet::kOther;
}

std::string plain_reader_name(const std::string &name) {
	// pcsc-lite appends " NN MM" (reader and slot numbers, hex).
	const size_t n = name.size();
	auto hexd = [&](size_t i) { return std::isxdigit(static_cast<unsigned char>(name[i])) != 0; };
	if (n > 6 && name[n - 6] == ' ' && hexd(n - 5) && hexd(n - 4) && name[n - 3] == ' ' && hexd(n - 2) &&
		hexd(n - 1)) {
		return name.substr(0, n - 6);
	}
	return name;
}

CardVerdict CardPolicy::check(const uint8_t *apdu, size_t len) const {
	Apdu a;
	if (!parse(apdu, len, &a)) {
		return refuse(kSwWrongLength, "send a malformed command", false);
	}
	const Class c = decode_class(a.cla);
	const bool known = applet_ == CardApplet::kPiv || applet_ == CardApplet::kOpenPgp;
	const bool unfiltered = pass_unknown_ && applet_ == CardApplet::kOther;
	if (!c.readable) {
		if (c.proprietary && unfiltered) {
			return pass();
		}
		return refuse(kSwSecurityNotSatisfied, "send a command of class " + hex_byte(a.cla), known);
	}
	if (c.channel != 0 || a.ins == 0x70) {
		// Only channel 0's selection is followed: another channel could
		// hold any applet.
		return refuse(kSwSecurityNotSatisfied, "use a logical channel", false);
	}
	if (c.secure && !unfiltered) {
		return refuse(kSwSecurityNotSatisfied, "use secure messaging, which the client can't read", known);
	}
	if (chain_ins_ >= 0 && a.ins == chain_ins_) {
		return pass();
	}
	if (a.ins == 0xa4) { // SELECT
		if (a.p1 != 0x04) { // by file ID or path
			if (pass_unknown_ && (applet_ == CardApplet::kOther || applet_ == CardApplet::kNone)) {
				return pass();
			}
			return refuse(kSwFileNotFound, "select a file", false);
		}
		if (a.data_len == 0) {
			return refuse(kSwFileNotFound, "select the card's default applet", false);
		}
		if ((a.p2 & 0x03) != 0) {
			return refuse(kSwFileNotFound, "select an applet by a later match", false);
		}
		CardApplet applet = applet_for_aid(a.data, a.data_len);
		if (applet == CardApplet::kPiv || applet == CardApplet::kOpenPgp ||
			(applet == CardApplet::kOther && pass_unknown_)) {
			return pass();
		}
		return refuse(kSwFileNotFound, "select applet " + hex(a.data, a.data_len), false);
	}
	if (a.ins == 0xc0) { // GET RESPONSE: the rest of a passed command's answer
		return pass();
	}

	auto ask = [&](CardConsent consent) {
		if (!allow_maintenance_) {
			return refuse(kSwSecurityNotSatisfied, consent_what(consent), true);
		}
		CardVerdict v;
		v.action = CardVerdict::kAsk;
		v.consent = std::move(consent);
		return v;
	};
	auto consent = [](CardConsent::Kind kind, std::string slot = "", std::string to_slot = "") {
		CardConsent c;
		c.kind = kind;
		c.slot = std::move(slot);
		c.to_slot = std::move(to_slot);
		return c;
	};
	auto unknown = [&](const char *applet) {
		return refuse(kSwSecurityNotSatisfied, std::string("send ") + applet + " command " + hex_byte(a.ins),
			true);
	};

	switch (applet_) {
	case CardApplet::kNone:
		if (pass_unknown_) {
			switch (a.ins) {
			case 0xb0: // READ BINARY
			case 0xb1:
			case 0xb2: // READ RECORD
			case 0xb3:
			case 0xca: // GET DATA
			case 0xcb: return pass();
			}
		}
		return refuse(kSwSecurityNotSatisfied, "send command " + hex_byte(a.ins) + " with no applet selected",
			false);
	case CardApplet::kOther: return pass();
	case CardApplet::kPiv:
		switch (a.ins) {
		case 0x20: // VERIFY
		case 0x87: // GENERAL AUTHENTICATE
		case 0xcb: // GET DATA
		case 0xfd: // Yubico GET VERSION
		case 0xf8: // Yubico GET SERIAL
		case 0xf7: // Yubico GET METADATA
		case 0xf9: // Yubico ATTEST
			return pass();
		case 0x47: return ask(consent(CardConsent::kPivGenerateKey, piv_slot(a.p2)));
		case 0xfe: return ask(consent(CardConsent::kPivImportKey, piv_slot(a.p2)));
		case 0xdb: {
			CardConsent w = consent(CardConsent::kPivWriteObject);
			piv_object(a, &w);
			return ask(std::move(w));
		}
		case 0x24:
			return ask(consent(a.p2 == 0x81 ? CardConsent::kPivChangePuk : CardConsent::kPivChangePin));
		case 0x2c: return ask(consent(CardConsent::kPivUnblockPin));
		case 0xff: return ask(consent(CardConsent::kPivSetManagementKey));
		case 0xfa: return ask(consent(CardConsent::kPivSetPinRetries));
		case 0xfb: return ask(consent(CardConsent::kPivReset));
		case 0xf6:
			if (a.p1 == 0xff) {
				return ask(consent(CardConsent::kPivDeleteKey, piv_slot(a.p2)));
			}
			return ask(consent(CardConsent::kPivMoveKey, piv_slot(a.p2), piv_slot(a.p1)));
		}
		return unknown("PIV");
	case CardApplet::kOpenPgp:
		switch (a.ins) {
		case 0x20: // VERIFY
		case 0x2a: // PERFORM SECURITY OPERATION: sign, decipher
		case 0x88: // INTERNAL AUTHENTICATE
		case 0x84: // GET CHALLENGE
		case 0xca: // GET DATA
		case 0xcc: // GET NEXT DATA
		case 0xa5: // SELECT DATA
		case 0x22: // MANAGE SECURITY ENVIRONMENT
		case 0xf1: // Yubico GET VERSION
		// ACTIVATE FILE does nothing to an applet in use; after an approved
		// TERMINATE DF it finishes the reset.
		case 0x44: return pass();
		case 0x47: // GENERATE ASYMMETRIC KEY PAIR: P1 81 reads a public key
			if (a.p1 == 0x81) {
				return pass();
			}
			if (a.p1 == 0x80) {
				return ask(consent(CardConsent::kPgpGenerateKey, a.data_len ? pgp_key(a.data[0]) : ""));
			}
			return unknown("OpenPGP");
		case 0xda: {
			CardConsent w = consent(CardConsent::kPgpWriteData);
			w.object = pgp_object(static_cast<uint16_t>(a.p1 << 8 | a.p2));
			return ask(std::move(w));
		}
		case 0xdb: return ask(consent(CardConsent::kPgpImportKey, pgp_import_key(a)));
		case 0x24:
			return ask(consent(a.p2 == 0x83 ? CardConsent::kPgpChangeAdminPin : CardConsent::kPgpChangePin));
		case 0x2c: return ask(consent(CardConsent::kPgpUnblockPin));
		case 0xf2: return ask(consent(CardConsent::kPgpSetPinRetries));
		case 0xfb: {
			const char *keys[] = {"", "signature", "decryption", "authentication"};
			return ask(consent(CardConsent::kPgpAttest, a.p1 <= 3 ? keys[a.p1] : ""));
		}
		case 0xe6: return ask(consent(CardConsent::kPgpTerminate));
		}
		return unknown("OpenPGP");
	}
	return unknown("card");
}

void CardPolicy::transmitted(const uint8_t *apdu, size_t len, const uint8_t *response, size_t response_len) {
	Apdu a;
	if (!parse(apdu, len, &a)) {
		return;
	}
	const uint16_t sw = response_len >= 2 ? static_cast<uint16_t>(response[response_len - 2] << 8 |
														  response[response_len - 1])
										  : 0;
	const bool ok = sw == 0x9000 || (sw >> 8) == 0x61;
	const Class c = decode_class(a.cla);
	chain_ins_ = c.readable && c.chained && ok ? a.ins : -1;
	if (c.readable && !c.chained && a.ins == 0xa4 && a.p1 == 0x04 && ok) {
		applet_ = applet_for_aid(a.data, a.data_len);
		aid_.assign(reinterpret_cast<const char *>(a.data), applet_ == CardApplet::kNone ? 0 : a.data_len);
	}
}

void CardPolicy::reset() {
	applet_ = CardApplet::kNone;
	aid_.clear();
	chain_ins_ = -1;
}

CardConsentText describe_card_consent(const CardConsent &c, const std::string &card_name) {
	const std::string card = card_name.empty() ? std::string("your smart card") : card_name;
	const std::string what = consent_what(c);
	auto text = [&](std::string title, std::string body, std::string allow, std::string deny = "Don't") {
		return CardConsentText{std::move(title), std::move(body), std::move(allow), std::move(deny), what};
	};
	const std::string pgp_key = c.slot.empty() ? "a key" : "the " + c.slot + " key";
	switch (c.kind) {
	case CardConsent::kPivGenerateKey:
		return text("Generate a new key on your smart card?",
			"The host wants to generate a new key in PIV slot " + c.slot + " on " + card +
				". This replaces the key there, and whatever used it stops working with it.",
			"Generate");
	case CardConsent::kPivImportKey:
		return text("Import a key onto your smart card?",
			"The host wants to store a private key it supplies in PIV slot " + c.slot + " on " + card +
				", replacing the key there.",
			"Import");
	case CardConsent::kPivWriteObject:
		if (!c.slot.empty()) {
			return text("Replace a certificate on your smart card?",
				"The host wants to write " + c.object + " on " + card + ", replacing the one there.", "Write");
		}
		return text("Change data on your smart card?", "The host wants to write " + c.object + " on " + card + ".",
			"Write");
	case CardConsent::kPivChangePin:
		return text("Change your smart card's PIN?",
			"The host wants to change the PIV PIN on " + card +
				". Allow this only if you're changing it yourself in the session.",
			"Change PIN");
	case CardConsent::kPivChangePuk:
		return text("Change your smart card's PUK?",
			"The host wants to change the PUK on " + card +
				", which unblocks its PIN. Allow this only if you're changing it yourself in the session.",
			"Change PUK");
	case CardConsent::kPivUnblockPin:
		return text("Reset your smart card's PIN?",
			"The host wants to set a new PIV PIN on " + card +
				" with its PUK, as for a blocked PIN. Allow this only if you're doing it yourself in the session.",
			"Reset PIN");
	case CardConsent::kPivSetManagementKey:
		return text("Change your smart card's management key?",
			"The host wants to change the PIV management key on " + card +
				". It guards writing keys and certificates; one you don't know stops you changing them until "
				"the card is reset.",
			"Change");
	case CardConsent::kPivSetPinRetries:
		return text("Change your smart card's PIN attempts?",
			"The host wants to change how many wrong PINs and PUKs " + card +
				" allows. This also resets the PIN and PUK to their factory defaults.",
			"Change");
	case CardConsent::kPivMoveKey:
		return text("Move a key on your smart card?",
			"The host wants to move the key in PIV slot " + c.slot + " on " + card + " to slot " + c.to_slot +
				", replacing the key there.",
			"Move");
	case CardConsent::kPivDeleteKey:
		return text("Delete a key from your smart card?",
			"The host wants to delete the key in PIV slot " + c.slot + " on " + card +
				". Whatever used it stops working, and it can't be undone.",
			"Delete", "Keep");
	case CardConsent::kPivReset:
		return text("Erase your smart card's PIV keys?",
			"The host wants to reset the PIV application on " + card +
				". This erases every PIV key and certificate on it and resets its PIN, PUK and management key, "
				"and it can't be undone.",
			"Erase", "Keep");
	case CardConsent::kPgpGenerateKey:
		return text("Generate a new OpenPGP key?",
			"The host wants to generate " + (c.slot.empty() ? std::string("a new OpenPGP key") : "a new OpenPGP " + c.slot + " key") +
				" on " + card + ". This replaces the key there, and what it encrypted or signed for stops "
				"working with it.",
			"Generate");
	case CardConsent::kPgpImportKey:
		return text("Import an OpenPGP key?",
			"The host wants to store a private key it supplies as " + pgp_key + " of the OpenPGP application on " +
				card + ", replacing the key there.",
			"Import");
	case CardConsent::kPgpWriteData:
		return text("Change data on your smart card?",
			"The host wants to change " + c.object + " in the OpenPGP application on " + card + ".", "Change");
	case CardConsent::kPgpChangePin:
		return text("Change your OpenPGP PIN?",
			"The host wants to change the OpenPGP PIN on " + card +
				". Allow this only if you're changing it yourself in the session.",
			"Change PIN");
	case CardConsent::kPgpChangeAdminPin:
		return text("Change your OpenPGP admin PIN?",
			"The host wants to change the OpenPGP admin PIN on " + card +
				". Allow this only if you're changing it yourself in the session.",
			"Change PIN");
	case CardConsent::kPgpUnblockPin:
		return text("Reset your OpenPGP PIN?",
			"The host wants to set a new OpenPGP PIN on " + card +
				", as for a blocked PIN. Allow this only if you're doing it yourself in the session.",
			"Reset PIN");
	case CardConsent::kPgpSetPinRetries:
		return text("Change your OpenPGP PIN attempts?",
			"The host wants to change how many wrong PINs the OpenPGP application on " + card + " allows.",
			"Change");
	case CardConsent::kPgpAttest:
		return text("Replace a certificate on your smart card?",
			"The host wants the OpenPGP application on " + card + " to attest " + pgp_key +
				", which replaces the certificate stored with it.",
			"Replace");
	case CardConsent::kPgpTerminate:
		return text("Erase your OpenPGP keys?",
			"The host wants to reset the OpenPGP application on " + card +
				". This erases every OpenPGP key on it and resets its PINs, and it can't be undone.",
			"Erase", "Keep");
	}
	return text("Allow this?", "The host wants to change " + card + ".", "Allow", "Deny");
}

} // namespace gdp
