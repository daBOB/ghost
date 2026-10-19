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
Bytes uint(uint64_t v) {
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

// Feeds a message's packets; the request, if the last one completed one.
bool feed_all(gdp::KeyRequestWatcher &w, const std::vector<Bytes> &ps, gdp::KeyRequest *req) {
	bool got = false;
	for (const Bytes &p : ps) {
		got = w.feed(p.data(), p.size(), req);
	}
	return got;
}

Bytes get_assertion(const std::string &rp, bool up) {
	return cat({{0x02},
		map(3, {uint(1), text(rp), uint(2), bytes(32), uint(5), map(1, {text("up"), up ? kTrue : kFalse})})});
}
Bytes make_credential(const std::string &rp) {
	// Long enough (a 64-byte user id) to take three packets.
	return cat({{0x01},
		map(4,
			{uint(1), bytes(32), uint(2), map(2, {text("id"), text(rp), text("name"), text("Example")}),
				uint(3), map(2, {text("id"), bytes(64), text("name"), text("joe")}), uint(4),
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
	gdp::KeyRequestWatcher w;
	gdp::KeyRequest req;
	assert(feed_all(w, packets(0x11223344, 0x90, get_assertion("github.com", true)), &req));
	assert(req.kind == gdp::KeyRequest::kSignIn && req.rp_id == "github.com");
	// A browser's silent probe for which credential the key holds.
	assert(!feed_all(w, packets(0x11223344, 0x90, get_assertion("github.com", false)), &req));
	std::vector<Bytes> reg = packets(0x11223344, 0x90, make_credential("example.com"));
	assert(reg.size() == 3);
	assert(feed_all(w, reg, &req));
	assert(req.kind == gdp::KeyRequest::kRegister && req.rp_id == "example.com");
	assert(feed_all(w, packets(1, 0x90, make_credential(".dummy")), &req));
	assert(req.kind == gdp::KeyRequest::kSelect && req.rp_id.empty());
	assert(feed_all(w, packets(1, 0x90, {0x0b}), &req) && req.kind == gdp::KeyRequest::kSelect);
	// GetInfo, an INIT, keep-alives: nothing to tell the user.
	assert(!feed_all(w, packets(1, 0x90, {0x04}), &req));
	assert(!feed_all(w, packets(0xffffffff, 0x86, Bytes(8, 1)), &req));
	// U2F: register, and authenticate unless it only checks a key handle.
	assert(
		feed_all(w, packets(1, 0x83, {0x00, 0x01, 0x03, 0x00}), &req) && req.kind == gdp::KeyRequest::kU2f);
	assert(feed_all(w, packets(1, 0x83, {0x00, 0x02, 0x03, 0x00}), &req));
	assert(!feed_all(w, packets(1, 0x83, {0x00, 0x02, 0x07, 0x00}), &req));
	// Two channels interleaved: each reassembled on its own.
	std::vector<Bytes> a = packets(0xa, 0x90, make_credential("a.example"));
	std::vector<Bytes> b = packets(0xb, 0x90, make_credential("b.example"));
	for (size_t i = 0; i < a.size(); i++) {
		bool got_a = w.feed(a[i].data(), a[i].size(), &req);
		assert(got_a == (i + 1 == a.size()));
		if (got_a) {
			assert(req.rp_id == "a.example");
		}
		bool got_b = w.feed(b[i].data(), b[i].size(), &req);
		if (got_b) {
			assert(req.rp_id == "b.example");
		}
	}
	// A continuation out of order drops the message, and the next one
	// starts clean.
	std::swap(reg[1], reg[2]);
	assert(!feed_all(w, reg, &req));
	assert(feed_all(w, packets(0x11223344, 0x90, get_assertion("github.com", true)), &req));
	// Garbage in a CBOR message: not reported, not a crash.
	assert(!feed_all(w, packets(1, 0x90, {0x02, 0xbf, 0xff}), &req));
	assert(!feed_all(w, packets(1, 0x90, {0x02, 0xa1, 0x01, 0x7a, 0xff, 0xff, 0xff, 0xff}), &req));

	printf("ok\n");
	return 0;
}
