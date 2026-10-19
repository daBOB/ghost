// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// gdp/security_key.hpp's descriptor check: the descriptors keys report,
// and the near misses a client must not forward.
#include "gdp/security_key.hpp"

#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool check(const std::vector<uint8_t> &rd) {
	return gdp::is_ctaphid_descriptor(rd.data(), rd.size());
}

// A little CBOR, in CTAP's canonical form.
using Bytes = std::vector<uint8_t>;
Bytes head(uint8_t major, uint64_t v) {
	Bytes out;
	if (v < 24) {
		out.push_back(uint8_t(major << 5 | v));
	} else if (v < 0x100) {
		out = {uint8_t(major << 5 | 24), uint8_t(v)};
	} else {
		out = {uint8_t(major << 5 | 25), uint8_t(v >> 8), uint8_t(v)};
	}
	return out;
}
Bytes cat(std::initializer_list<Bytes> parts) {
	Bytes out;
	for (const Bytes &p : parts) {
		out.insert(out.end(), p.begin(), p.end());
	}
	return out;
}
Bytes cint(uint64_t v) {
	return head(0, v);
}
Bytes text(const std::string &s) {
	Bytes out = head(3, s.size());
	out.insert(out.end(), s.begin(), s.end());
	return out;
}
Bytes bytes(size_t n) {
	Bytes out = head(2, n);
	out.resize(out.size() + n, 0xab);
	return out;
}
Bytes map(size_t pairs, std::initializer_list<Bytes> items) {
	return cat({head(5, pairs), cat(items)});
}
const Bytes kTrue = {0xf5}, kFalse = {0xf4};

// One CTAPHID message on channel `cid`, as packets.
std::vector<Bytes> packets(uint32_t cid, uint8_t cmd, const Bytes &msg) {
	std::vector<Bytes> out;
	Bytes p(64, 0);
	p[0] = uint8_t(cid >> 24), p[1] = uint8_t(cid >> 16), p[2] = uint8_t(cid >> 8), p[3] = uint8_t(cid);
	p[4] = cmd, p[5] = uint8_t(msg.size() >> 8), p[6] = uint8_t(msg.size());
	size_t at = std::min<size_t>(msg.size(), 57);
	std::copy(msg.begin(), msg.begin() + at, p.begin() + 7);
	out.push_back(p);
	for (uint8_t seq = 0; at < msg.size(); seq++) {
		Bytes c(64, 0);
		std::copy(p.begin(), p.begin() + 4, c.begin());
		c[4] = seq;
		size_t n = std::min<size_t>(msg.size() - at, 59);
		std::copy(msg.begin() + at, msg.begin() + at + n, c.begin() + 5);
		at += n;
		out.push_back(c);
	}
	return out;
}

// Feeds a message's packets. True when the last one passed a message to
// the key, with every packet of it, in order, and nothing before; `*v` is
// the last verdict.
bool feed_all(gdp::KeyPolicy &w, const std::vector<Bytes> &ps, gdp::KeyVerdict *v) {
	for (size_t i = 0; i < ps.size(); i++) {
		w.feed(ps[i].data(), ps[i].size(), v);
		if (i + 1 < ps.size()) {
			assert(v->to_key.empty() && v->to_host.empty());
		}
	}
	if (v->to_key.empty()) {
		return false;
	}
	assert(v->to_key.size() == ps.size());
	for (size_t i = 0; i < ps.size(); i++) {
		assert(std::equal(ps[i].begin(), ps[i].end(), v->to_key[i].begin()));
	}
	return true;
}

// A message that passed and will wait for a touch: `*req` says what for.
bool noticed(gdp::KeyPolicy &w, const std::vector<Bytes> &ps, gdp::KeyRequest *req) {
	gdp::KeyVerdict v;
	bool passed = feed_all(w, ps, &v);
	assert(passed && !v.refused);
	*req = v.request;
	return v.notice;
}

// A message refused on the host's behalf: nothing reached the key, and
// the host got a one-byte reply of `cmd` with `status` on the channel.
bool refused(gdp::KeyPolicy &w, const std::vector<Bytes> &ps, uint8_t cmd, uint8_t status,
	std::string *what) {
	gdp::KeyVerdict v;
	for (const Bytes &p : ps) {
		w.feed(p.data(), p.size(), &v);
		assert(v.to_key.empty());
	}
	if (!v.refused) {
		return false;
	}
	assert(v.to_host.size() == 1);
	const gdp::KeyPacket &r = v.to_host[0];
	assert(std::equal(ps[0].begin(), ps[0].begin() + 4, r.begin())); // the channel
	assert(r[4] == cmd && r[5] == 0 && r[6] == 1 && r[7] == status);
	*what = v.refused_what;
	return true;
}

Bytes client_pin(uint64_t sub) {
	return cat({{0x06}, map(2, {cint(1), cint(2), cint(2), cint(sub)})});
}
Bytes get_assertion(const std::string &rp, bool up) {
	return cat({{0x02},
		map(3, {cint(1), text(rp), cint(2), bytes(32), cint(5), map(1, {text("up"), up ? kTrue : kFalse})})});
}
Bytes make_credential(const std::string &rp) {
	// Long enough (a 64-byte user id) to take three packets.
	return cat({{0x01},
		map(4,
			{cint(1), bytes(32), cint(2), map(2, {text("id"), text(rp), text("name"), text("Example")}),
				cint(3), map(2, {text("id"), bytes(64), text("name"), text("joe")}), cint(4),
				cat({head(4, 1), map(2, {text("alg"), {0x26}, text("type"), text("public-key")})})})});
}

} // namespace

int main() {
	// A YubiKey 5's FIDO interface, byte for byte: also gdp-spec.md
	// §8.7's fixed descriptor.
	const std::vector<uint8_t> yubikey = {0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00,
		0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75,
		0x08, 0x95, 0x40, 0x91, 0x02, 0xc0};
	assert(check(yubikey));

	// Spelled differently: logical maximum as a one-byte item, the report
	// size and count set once for both reports, a usage with its page in
	// its own four bytes.
	const std::vector<uint8_t> terse = {0x0b, 0x01, 0x00, 0xd0, 0xf1, 0xa1, 0x01, 0x15, 0x00, 0x25, 0xff,
		0x75, 0x08, 0x95, 0x40, 0x09, 0x20, 0x81, 0x02, 0x09, 0x21, 0x91, 0x02, 0xc0};
	assert(check(terse));

	// 32-byte reports.
	std::vector<uint8_t> small = yubikey;
	small[17] = 0x20;
	small[30] = 0x20;
	assert(!check(small));
	// A report ID.
	std::vector<uint8_t> numbered = yubikey;
	numbered.insert(numbered.begin() + 7, {0x85, 0x01});
	assert(!check(numbered));
	// A feature report besides.
	std::vector<uint8_t> feature = yubikey;
	feature.insert(feature.end() - 1, {0x09, 0x22, 0xb1, 0x02});
	assert(!check(feature));
	// Another page: a keyboard collection after the FIDO one, or instead
	// of it.
	std::vector<uint8_t> two = yubikey;
	two.insert(two.end(), {0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0xc0});
	assert(!check(two));
	std::vector<uint8_t> keyboard = yubikey;
	keyboard[1] = 0x01;
	keyboard[2] = 0x00;
	keyboard[4] = 0x06;
	assert(!check(keyboard));
	// Truncated, unbalanced, empty.
	assert(!check(std::vector<uint8_t>(yubikey.begin(), yubikey.end() - 2)));
	assert(!check(std::vector<uint8_t>(yubikey.begin(), yubikey.end() - 1)));
	assert(!check({}));

	// The requests a touch will approve, and the site each names.
	gdp::KeyPolicy w;
	gdp::KeyRequest req;
	gdp::KeyVerdict v;
	assert(noticed(w, packets(0x11223344, 0x90, get_assertion("github.com", true)), &req));
	assert(req.kind == gdp::KeyRequest::kSignIn && req.rp_id == "github.com");
	// A browser's silent probe for which credential the key holds passes
	// without a notice.
	assert(!noticed(w, packets(0x11223344, 0x90, get_assertion("github.com", false)), &req));
	std::vector<Bytes> reg = packets(0x11223344, 0x90, make_credential("example.com"));
	assert(reg.size() == 3);
	assert(noticed(w, reg, &req));
	assert(req.kind == gdp::KeyRequest::kRegister && req.rp_id == "example.com");
	assert(noticed(w, packets(1, 0x90, make_credential(".dummy")), &req));
	assert(req.kind == gdp::KeyRequest::kSelect && req.rp_id.empty());
	assert(noticed(w, packets(1, 0x90, {0x0b}), &req) && req.kind == gdp::KeyRequest::kSelect);
	// GetInfo, GetNextAssertion, an INIT, a CANCEL, a PING, a WINK, a
	// PIN-gated sign-in's ClientPIN subcommands: passed, nothing to tell.
	assert(!noticed(w, packets(1, 0x90, {0x04}), &req));
	assert(!noticed(w, packets(1, 0x90, {0x08}), &req));
	assert(!noticed(w, packets(1, 0x90, {0x0c, 0xa1, 0x01, 0x00}), &req));
	assert(!noticed(w, packets(0xffffffff, 0x86, Bytes(8, 1)), &req));
	assert(!noticed(w, packets(1, 0x91, {}), &req));
	assert(!noticed(w, packets(1, 0x81, Bytes(100, 7)), &req));
	assert(!noticed(w, packets(1, 0x88, {}), &req));
	for (uint64_t sub : {1, 2, 5, 6, 7, 9}) {
		assert(!noticed(w, packets(1, 0x90, client_pin(sub)), &req));
	}
	// U2F: register, and authenticate unless it only checks a key handle.
	assert(noticed(w, packets(1, 0x83, {0x00, 0x01, 0x03, 0x00}), &req) && req.kind == gdp::KeyRequest::kU2f);
	assert(noticed(w, packets(1, 0x83, {0x00, 0x02, 0x03, 0x00}), &req));
	assert(!noticed(w, packets(1, 0x83, {0x00, 0x02, 0x07, 0x00}), &req));

	// Maintenance is refused in the key's place: CTAP2_ERR_OPERATION_DENIED
	// on the channel, and the key never sees a packet of it.
	std::string what;
	assert(refused(w, packets(1, 0x90, {0x07}), 0x90, 0x27, &what) && what == "reset it");
	assert(refused(w, packets(1, 0x90, client_pin(3)), 0x90, 0x27, &what) && what == "set or change its PIN");
	assert(refused(w, packets(1, 0x90, client_pin(4)), 0x90, 0x27, &what));
	// A ClientPIN whose subcommand can't be read is refused rather than
	// passed; a long one (three packets) is held and refused whole.
	assert(refused(w, packets(1, 0x90, {0x06, 0xa1, 0x01, 0x02}), 0x90, 0x27, &what));
	std::vector<Bytes> set_pin = packets(1, 0x90,
		cat({{0x06}, map(4, {cint(1), cint(2), cint(2), cint(3), cint(3), bytes(65), cint(5), bytes(64)})}));
	assert(set_pin.size() == 3);
	assert(refused(w, set_pin, 0x90, 0x27, &what) && what == "set or change its PIN");
	for (uint8_t cmd : {0x0a, 0x41}) {
		assert(refused(w, packets(1, 0x90, {cmd, 0xa1, 0x01, 0x01}), 0x90, 0x27, &what) &&
			what == "manage its credentials");
	}
	for (uint8_t cmd : {0x09, 0x40}) {
		assert(refused(w, packets(1, 0x90, {cmd}), 0x90, 0x27, &what) && what == "enrol fingerprints on it");
	}
	assert(refused(w, packets(1, 0x90, {0x0d, 0xa1, 0x01, 0x02}), 0x90, 0x27, &what) &&
		what == "change its configuration");
	assert(refused(w, packets(1, 0x90, {0x50}), 0x90, 0x27, &what) && what == "send it command 0x50");
	// A CTAPHID command outside the set (a vendor one, a KEEPALIVE the host
	// has no business sending): CTAPHID_ERROR, ERR_INVALID_CMD.
	assert(
		refused(w, packets(1, 0xc0, {1, 2, 3}), 0xbf, 0x01, &what) && what == "send it CTAPHID command 0x40");
	assert(refused(w, packets(1, 0xbb, {1}), 0xbf, 0x01, &what));
	// After a refusal the channel is clean.
	assert(noticed(w, packets(1, 0x90, get_assertion("github.com", true)), &req));

	// Two channels interleaved: each held and passed on its own, with its
	// own packets.
	std::vector<Bytes> a = packets(0xa, 0x90, make_credential("a.example"));
	std::vector<Bytes> b = packets(0xb, 0x90, make_credential("b.example"));
	for (size_t i = 0; i < a.size(); i++) {
		w.feed(a[i].data(), a[i].size(), &v);
		assert(v.to_key.empty() == (i + 1 < a.size()));
		if (!v.to_key.empty()) {
			assert(v.notice && v.request.rp_id == "a.example" && v.to_key.size() == a.size());
			assert(std::equal(a[1].begin(), a[1].end(), v.to_key[1].begin()));
		}
		w.feed(b[i].data(), b[i].size(), &v);
		if (!v.to_key.empty()) {
			assert(v.request.rp_id == "b.example");
		}
	}
	// A continuation out of order drops the message with ERR_INVALID_SEQ
	// (nothing of it reached the key), and the next one starts clean.
	std::swap(reg[1], reg[2]);
	w.feed(reg[0].data(), reg[0].size(), &v);
	w.feed(reg[1].data(), reg[1].size(), &v);
	assert(v.to_key.empty() && !v.refused && v.to_host.size() == 1 && v.to_host[0][4] == 0xbf &&
		v.to_host[0][7] == 0x04);
	w.feed(reg[2].data(), reg[2].size(), &v); // an orphan continuation: ignored
	assert(v.to_key.empty() && v.to_host.empty());
	assert(noticed(w, packets(0x11223344, 0x90, get_assertion("github.com", true)), &req));
	// A length no message can have: ERR_INVALID_LEN.
	std::vector<Bytes> huge = packets(1, 0x90, {0x04});
	huge[0][5] = 0xff, huge[0][6] = 0xff;
	w.feed(huge[0].data(), huge[0].size(), &v);
	assert(v.to_key.empty() && v.to_host.size() == 1 && v.to_host[0][7] == 0x03);
	// A CANCEL in the middle of a message passes at once and clears it.
	w.feed(a[0].data(), a[0].size(), &v);
	assert(feed_all(w, packets(0xa, 0x91, {}), &v));
	w.feed(a[1].data(), a[1].size(), &v);
	assert(v.to_key.empty() && v.to_host.empty());
	// Garbage in a CBOR message: passed to the key to refuse (a sign-in
	// command), not a crash; a short packet is ignored.
	assert(!noticed(w, packets(1, 0x90, {0x02, 0xbf, 0xff}), &req));
	assert(!noticed(w, packets(1, 0x90, {0x02, 0xa1, 0x01, 0x7a, 0xff, 0xff, 0xff, 0xff}), &req));
	w.feed(a[0].data(), 10, &v);
	assert(v.to_key.empty() && v.to_host.empty());

	printf("ok\n");
	return 0;
}
