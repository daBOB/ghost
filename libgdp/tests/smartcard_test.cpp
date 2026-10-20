// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// gdp/smartcard.hpp's CardPolicy: what a host may send a forwarded card's
// PIV and OpenPGP applets, what it asks about, and what it never passes.
#include "gdp/smartcard.hpp"

#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<uint8_t>;
using gdp::CardApplet;
using gdp::CardConsent;
using gdp::CardPolicy;
using gdp::CardVerdict;

Bytes apdu(uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, const Bytes &data = {}, bool le = false) {
	Bytes out = {cla, ins, p1, p2};
	if (!data.empty()) {
		out.push_back(uint8_t(data.size()));
		out.insert(out.end(), data.begin(), data.end());
	}
	if (le) {
		out.push_back(0);
	}
	return out;
}

const Bytes kPiv = {0xa0, 0x00, 0x00, 0x03, 0x08};
const Bytes kOpenPgp = {0xd2, 0x76, 0x00, 0x01, 0x24, 0x01};
const Bytes kOk = {0x90, 0x00};

CardVerdict check(const CardPolicy &p, const Bytes &a) {
	return p.check(a.data(), a.size());
}

// Passes `a` to the "card", which answers `sw`.
void transmit(CardPolicy &p, const Bytes &a, const Bytes &sw = kOk) {
	p.transmitted(a.data(), a.size(), sw.data(), sw.size());
}

void select(CardPolicy &p, const Bytes &aid) {
	Bytes a = apdu(0x00, 0xa4, 0x04, 0x00, aid);
	assert(check(p, a).action == CardVerdict::kPass);
	transmit(p, a);
}

bool passes(const CardPolicy &p, const Bytes &a) {
	return check(p, a).action == CardVerdict::kPass;
}

void test_aids() {
	auto applet = [](const Bytes &aid) { return gdp::applet_for_aid(aid.data(), aid.size()); };
	assert(applet(kPiv) == CardApplet::kPiv);
	assert(applet({0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}) == CardApplet::kPiv);
	assert(applet(kOpenPgp) == CardApplet::kOpenPgp);
	// The full AID, with a YubiKey's version, manufacturer and serial.
	assert(applet({0xd2, 0x76, 0x00, 0x01, 0x24, 0x01, 0x03, 0x04, 0x00, 0x06, 0x01, 0x02, 0x03, 0x04, 0x00,
			   0x00}) == CardApplet::kOpenPgp);
	// Yubico's management, OATH and OTP applets; FIDO; GlobalPlatform.
	assert(applet({0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}) == CardApplet::kNone);
	assert(applet({0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}) == CardApplet::kNone);
	assert(applet({0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01}) == CardApplet::kNone);
	assert(applet({0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01}) == CardApplet::kNone);
	assert(applet({0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00}) == CardApplet::kNone);
	// A prefix that a card could match to any of those, by partial selection.
	assert(applet({0xa0, 0x00, 0x00}) == CardApplet::kNone);
	assert(applet({0xa0}) == CardApplet::kNone);
	assert(applet({0xa0, 0x00, 0x00, 0x03}) == CardApplet::kNone);
	// Something else: a CAC applet, a payment card.
	assert(applet({0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00}) == CardApplet::kOther);
	assert(applet({0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10}) == CardApplet::kOther);
	assert(applet({}) == CardApplet::kNone);
}

void test_select() {
	CardPolicy p;
	assert(p.applet() == CardApplet::kNone);
	// Nothing but SELECT and GET RESPONSE before an applet is selected.
	CardVerdict v = check(p, apdu(0x00, 0xcb, 0x3f, 0xff, {0x5c, 0x01, 0x7e}));
	assert(v.action == CardVerdict::kRefuse && v.status == gdp::kSwSecurityNotSatisfied && !v.notify);
	// The management applet: refused like a card without it would.
	v = check(p, apdu(0x00, 0xa4, 0x04, 0x00, {0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17}));
	assert(v.action == CardVerdict::kRefuse && v.status == gdp::kSwFileNotFound);
	assert(v.refused_what == "select applet a000000527471117");
	// An unknown applet, by file, by the default, by next occurrence.
	assert(check(p, apdu(0x00, 0xa4, 0x04, 0x00, {0xa0, 0x00, 0x00, 0x00, 0x79, 0x01})).status ==
		gdp::kSwFileNotFound);
	assert(check(p, apdu(0x00, 0xa4, 0x00, 0x0c, {0x3f, 0x00})).status == gdp::kSwFileNotFound);
	assert(check(p, apdu(0x00, 0xa4, 0x04, 0x00, {}, true)).status == gdp::kSwFileNotFound);
	assert(check(p, apdu(0x00, 0xa4, 0x04, 0x02, kPiv)).status == gdp::kSwFileNotFound);

	// A SELECT the card turns down leaves what was selected.
	Bytes sel = apdu(0x00, 0xa4, 0x04, 0x00, kPiv);
	assert(passes(p, sel));
	transmit(p, sel, {0x6a, 0x82});
	assert(p.applet() == CardApplet::kNone);
	transmit(p, sel, {0x61, 0x10});
	assert(p.applet() == CardApplet::kPiv);
	select(p, kOpenPgp);
	assert(p.applet() == CardApplet::kOpenPgp);
	assert(p.selected_aid() == std::string(kOpenPgp.begin(), kOpenPgp.end()));
	// A refused SELECT never reached the card, so nothing changes.
	assert(!passes(p, apdu(0x00, 0xa4, 0x04, 0x00, {0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01})));
	assert(p.applet() == CardApplet::kOpenPgp);
	p.reset();
	assert(p.applet() == CardApplet::kNone && p.selected_aid().empty());
	assert(passes(p, apdu(0x00, 0xc0, 0x00, 0x00, {}, true)));
}

void test_piv() {
	CardPolicy p;
	select(p, kPiv);
	// What signing in, ykman piv info and pkcs11-tool -O send.
	assert(passes(p, apdu(0x00, 0xcb, 0x3f, 0xff, {0x5c, 0x03, 0x5f, 0xc1, 0x05}, true)));
	assert(passes(p, apdu(0x00, 0x20, 0x00, 0x80, {'1', '2', '3', '4', '5', '6', 0xff, 0xff})));
	assert(passes(p, apdu(0x00, 0x20, 0x00, 0x80)));
	assert(passes(p, apdu(0x00, 0x87, 0x11, 0x9a, {0x7c, 0x04, 0x82, 0x00, 0x81, 0x00}, true)));
	assert(passes(p, apdu(0x00, 0xfd, 0x00, 0x00)));
	assert(passes(p, apdu(0x00, 0xf8, 0x00, 0x00)));
	assert(passes(p, apdu(0x00, 0xf7, 0x00, 0x9a)));
	assert(passes(p, apdu(0x00, 0xf9, 0x9a, 0x00)));
	assert(passes(p, apdu(0x00, 0xc0, 0x00, 0x00)));

	CardVerdict v = check(p, apdu(0x00, 0x47, 0x00, 0x9a, {0xac, 0x03, 0x80, 0x01, 0x11}));
	assert(v.action == CardVerdict::kAsk && v.consent.kind == CardConsent::kPivGenerateKey);
	assert(v.consent.slot == "9A (authentication)");
	gdp::CardConsentText t = gdp::describe_card_consent(v.consent, "Yubico YubiKey OTP+FIDO+CCID");
	assert(t.what == "generate a new PIV key in slot 9A (authentication)");
	assert(t.body.find("Yubico YubiKey OTP+FIDO+CCID") != std::string::npos);
	assert(t.allow_label == "Generate" && t.deny_label == "Don't");

	v = check(p, apdu(0x00, 0xdb, 0x3f, 0xff, {0x5c, 0x03, 0x5f, 0xc1, 0x0a, 0x53, 0x00}));
	assert(v.action == CardVerdict::kAsk && v.consent.kind == CardConsent::kPivWriteObject);
	assert(v.consent.object == "the certificate for slot 9C (signature)");
	v = check(p, apdu(0x00, 0xdb, 0x3f, 0xff, {0x5c, 0x03, 0x5f, 0xc1, 0x0e, 0x53, 0x00}));
	assert(v.consent.slot == "83 (retired key 2)");
	v = check(p, apdu(0x00, 0xdb, 0x3f, 0xff, {0x5c, 0x03, 0x5f, 0xc1, 0x02, 0x53, 0x00}));
	assert(v.consent.object == "the card's ID (CHUID)" && v.consent.slot.empty());

	assert(check(p, apdu(0x00, 0x24, 0x00, 0x80, Bytes(16, '1'))).consent.kind == CardConsent::kPivChangePin);
	assert(check(p, apdu(0x00, 0x24, 0x00, 0x81, Bytes(16, '1'))).consent.kind == CardConsent::kPivChangePuk);
	assert(check(p, apdu(0x00, 0x2c, 0x00, 0x80, Bytes(16, '1'))).consent.kind == CardConsent::kPivUnblockPin);
	assert(check(p, apdu(0x00, 0xff, 0xff, 0xff, Bytes(27, 0))).consent.kind ==
		CardConsent::kPivSetManagementKey);
	assert(check(p, apdu(0x00, 0xfe, 0x11, 0x9c, Bytes(20, 0))).consent.kind == CardConsent::kPivImportKey);
	assert(check(p, apdu(0x00, 0xfa, 0x05, 0x05)).consent.kind == CardConsent::kPivSetPinRetries);
	assert(check(p, apdu(0x00, 0xfb, 0x00, 0x00)).consent.kind == CardConsent::kPivReset);
	v = check(p, apdu(0x00, 0xf6, 0xff, 0x9d));
	assert(v.consent.kind == CardConsent::kPivDeleteKey && v.consent.slot == "9D (key management)");
	v = check(p, apdu(0x00, 0xf6, 0x82, 0x9a));
	assert(v.consent.kind == CardConsent::kPivMoveKey && v.consent.to_slot == "82 (retired key 1)");

	// An instruction PIV doesn't have.
	v = check(p, apdu(0x00, 0xd6, 0x00, 0x00, {0x01}));
	assert(v.action == CardVerdict::kRefuse && v.status == gdp::kSwSecurityNotSatisfied && v.notify);
	assert(v.refused_what == "send PIV command D6");
}

void test_openpgp() {
	CardPolicy p;
	select(p, kOpenPgp);
	assert(passes(p, apdu(0x00, 0xca, 0x00, 0x6e, {}, true)));
	assert(passes(p, apdu(0x00, 0x20, 0x00, 0x81, {'1', '2', '3', '4', '5', '6'})));
	assert(passes(p, apdu(0x00, 0x2a, 0x9e, 0x9a, Bytes(32, 1), true)));
	assert(passes(p, apdu(0x00, 0x2a, 0x80, 0x86, Bytes(64, 1), true)));
	assert(passes(p, apdu(0x00, 0x88, 0x00, 0x00, Bytes(32, 1), true)));
	assert(passes(p, apdu(0x00, 0x47, 0x81, 0x00, {0xb6, 0x00}, true)));
	assert(passes(p, apdu(0x00, 0x44, 0x00, 0x00)));
	assert(passes(p, apdu(0x00, 0xf1, 0x00, 0x00)));

	CardVerdict v = check(p, apdu(0x00, 0x47, 0x80, 0x00, {0xb8, 0x00}, true));
	assert(v.action == CardVerdict::kAsk && v.consent.kind == CardConsent::kPgpGenerateKey);
	assert(v.consent.slot == "decryption");
	v = check(p, apdu(0x00, 0xda, 0x00, 0x5b, {'J', 'o'}));
	assert(v.consent.kind == CardConsent::kPgpWriteData && v.consent.object == "the cardholder's name");
	v = check(p, apdu(0x00, 0xda, 0x00, 0xd6, {0x01, 0x20}));
	assert(v.consent.object == "the signature key's touch policy");
	v = check(p, apdu(0x00, 0xdb, 0x3f, 0xff, {0x4d, 0x82, 0x01, 0x00, 0xa4, 0x00}));
	assert(v.consent.kind == CardConsent::kPgpImportKey && v.consent.slot == "authentication");
	assert(check(p, apdu(0x00, 0x24, 0x00, 0x81, Bytes(12, '1'))).consent.kind == CardConsent::kPgpChangePin);
	assert(check(p, apdu(0x00, 0x24, 0x00, 0x83, Bytes(16, '1'))).consent.kind ==
		CardConsent::kPgpChangeAdminPin);
	assert(check(p, apdu(0x00, 0x2c, 0x02, 0x81, Bytes(6, '1'))).consent.kind == CardConsent::kPgpUnblockPin);
	assert(check(p, apdu(0x00, 0xe6, 0x00, 0x00)).consent.kind == CardConsent::kPgpTerminate);
	v = check(p, apdu(0x00, 0xfb, 0x01, 0x00));
	assert(v.consent.kind == CardConsent::kPgpAttest && v.consent.slot == "signature");
	assert(!passes(p, apdu(0x00, 0x47, 0x82, 0x00, {0xb6, 0x00})));
	// PIV's instructions mean nothing here.
	assert(check(p, apdu(0x00, 0xfd, 0x00, 0x00)).action == CardVerdict::kRefuse);
}

void test_classes() {
	CardPolicy p;
	select(p, kPiv);
	// Logical channel 1, secure messaging, proprietary and reader classes.
	CardVerdict v = check(p, apdu(0x01, 0xcb, 0x3f, 0xff, {0x5c, 0x01, 0x7e}));
	assert(v.action == CardVerdict::kRefuse && v.refused_what == "use a logical channel");
	assert(check(p, apdu(0x00, 0x70, 0x00, 0x00, {}, true)).action == CardVerdict::kRefuse);
	assert(check(p, apdu(0x41, 0xa4, 0x04, 0x00, kPiv)).action == CardVerdict::kRefuse);
	v = check(p, apdu(0x0c, 0xcb, 0x3f, 0xff, {0x5c, 0x01, 0x7e}));
	assert(v.action == CardVerdict::kRefuse && v.notify);
	assert(check(p, apdu(0x84, 0x82, 0x33, 0x00, Bytes(16, 0))).action == CardVerdict::kRefuse);
	assert(check(p, apdu(0xff, 0xca, 0x00, 0x00, {}, true)).action == CardVerdict::kRefuse);
	assert(check(p, apdu(0x20, 0xcb, 0x3f, 0xff, {0x5c, 0x01, 0x7e})).action == CardVerdict::kRefuse);
	// Malformed: Lc says more than there is.
	Bytes bad = {0x00, 0xcb, 0x3f, 0xff, 0x05, 0x5c};
	v = check(p, bad);
	assert(v.action == CardVerdict::kRefuse && v.status == gdp::kSwWrongLength);
	// An extended APDU is read too.
	Bytes ext = {0x00, 0xdb, 0x3f, 0xff, 0x00, 0x00, 0x07, 0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x53, 0x00};
	v = check(p, ext);
	assert(v.action == CardVerdict::kAsk && v.consent.slot == "9A (authentication)");
}

void test_chaining() {
	CardPolicy p;
	select(p, kPiv);
	// A certificate too big for one short APDU: the chain's first block
	// asks, and the rest pass once it reached the card.
	Bytes first = apdu(0x10, 0xdb, 0x3f, 0xff, {0x5c, 0x03, 0x5f, 0xc1, 0x05, 0x53, 0x82, 0x04, 0x00});
	Bytes middle = apdu(0x10, 0xdb, 0x3f, 0xff, Bytes(255, 0x30));
	Bytes last = apdu(0x00, 0xdb, 0x3f, 0xff, Bytes(100, 0x30));
	CardVerdict v = check(p, first);
	assert(v.action == CardVerdict::kAsk && v.consent.slot == "9A (authentication)");
	// Not yet transmitted: the next block is classified on its own.
	assert(check(p, middle).action == CardVerdict::kAsk);
	transmit(p, first);
	assert(passes(p, middle));
	transmit(p, middle);
	assert(passes(p, last));
	transmit(p, last);
	// The chain is over.
	assert(check(p, last).action == CardVerdict::kAsk);
	// A chain the card refused part-way passes no further.
	transmit(p, first);
	transmit(p, middle, {0x6a, 0x80});
	assert(check(p, middle).action == CardVerdict::kAsk);
	// Another command breaks a chain.
	transmit(p, first);
	assert(passes(p, apdu(0x00, 0xcb, 0x3f, 0xff, {0x5c, 0x01, 0x7e})));
	transmit(p, apdu(0x00, 0xcb, 0x3f, 0xff, {0x5c, 0x01, 0x7e}));
	assert(check(p, middle).action == CardVerdict::kAsk);
}

void test_no_maintenance() {
	CardPolicy p(false, false);
	select(p, kPiv);
	CardVerdict v = check(p, apdu(0x00, 0xfb, 0x00, 0x00));
	assert(v.action == CardVerdict::kRefuse && v.status == gdp::kSwSecurityNotSatisfied && v.notify);
	assert(v.refused_what == "erase every PIV key and certificate");
	assert(passes(p, apdu(0x00, 0x87, 0x11, 0x9a, {0x7c, 0x00})));
}

void test_pass_unknown() {
	CardPolicy p(true, true);
	// A file-system card: files, and reading them, with nothing selected.
	assert(passes(p, apdu(0x00, 0xa4, 0x00, 0x0c, {0x3f, 0x00})));
	assert(passes(p, apdu(0x00, 0xb0, 0x00, 0x00, {}, true)));
	// Writing needs an applet the host selected.
	assert(!passes(p, apdu(0x00, 0xd6, 0x00, 0x00, {0x01})));
	// A CAC applet passes unfiltered, writes, proprietary classes and all.
	select(p, {0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00});
	assert(p.applet() == CardApplet::kOther);
	assert(passes(p, apdu(0x00, 0xd6, 0x00, 0x00, {0x01})));
	assert(passes(p, apdu(0x80, 0x36, 0x00, 0x00, {}, true)));
	assert(passes(p, apdu(0x0c, 0xb0, 0x00, 0x00, {0x01})));
	// The applets refused at SELECT stay refused; so do other channels.
	assert(!passes(p, apdu(0x00, 0xa4, 0x04, 0x00, {0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01})));
	assert(!passes(p, apdu(0x00, 0xa4, 0x04, 0x00, {0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01})));
	assert(!passes(p, apdu(0x01, 0xa4, 0x04, 0x00, {0xa0, 0x00, 0x00, 0x00, 0x79, 0x01, 0x00})));
	assert(!passes(p, apdu(0x00, 0xa4, 0x04, 0x00, {}, true)));
	// PIV still gets its own policy.
	select(p, kPiv);
	assert(check(p, apdu(0x00, 0xfb, 0x00, 0x00)).action == CardVerdict::kAsk);
}

void test_reader_name() {
	assert(gdp::plain_reader_name("Yubico YubiKey OTP+FIDO+CCID 00 00") == "Yubico YubiKey OTP+FIDO+CCID");
	assert(gdp::plain_reader_name("Yubico YubiKey OTP+FIDO+CCID 0") == "Yubico YubiKey OTP+FIDO+CCID 0");
	assert(gdp::plain_reader_name("Reader 1A 0F") == "Reader");
	assert(gdp::plain_reader_name("00 00") == "00 00");
}

} // namespace

int main() {
	test_aids();
	test_select();
	test_piv();
	test_openpgp();
	test_classes();
	test_chaining();
	test_no_maintenance();
	test_pass_unknown();
	test_reader_name();
	std::printf("smartcard_test: ok\n");
	return 0;
}
