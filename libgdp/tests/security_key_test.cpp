// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// gdp/security_key.hpp's descriptor check: the descriptors keys report,
// and the near misses a client must not forward.
#include "gdp/security_key.hpp"

#undef NDEBUG
#include <cassert>
#include <cstdio>
#include <vector>

namespace {

bool check(const std::vector<uint8_t> &rd) {
	return gdp::is_ctaphid_descriptor(rd.data(), rd.size());
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

	printf("ok\n");
	return 0;
}
