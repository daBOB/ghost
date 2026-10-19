// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/security_key.hpp"

namespace gdp {

bool is_ctaphid_descriptor(const uint8_t *rd, size_t len) {
	constexpr uint32_t kCtaphid = (uint32_t(kFidoUsagePage) << 16) | kFidoUsageCtaphid;
	constexpr uint32_t kPacketBits = kSecurityKeyPacket * 8;
	uint32_t page = 0, report_size = 0, report_count = 0;
	uint32_t last_usage = 0;
	bool have_usage = false;
	int depth = 0;
	bool found = false, inside = false;
	uint32_t input_bits = 0, output_bits = 0;
	size_t i = 0;
	while (i < len) {
		uint8_t prefix = rd[i];
		if (prefix == 0xfe) {
			return false; // a long item: nothing defines one
		}
		size_t size = (prefix & 3) == 3 ? 4 : (prefix & 3);
		if (i + 1 + size > len) {
			return false;
		}
		uint32_t value = 0;
		for (size_t b = size; b > 0; b--) {
			value = (value << 8) | rd[i + b];
		}
		i += 1 + size;
		uint8_t type = (prefix >> 2) & 3, tag = prefix >> 4;
		switch (type) {
		case 0: // Main
			switch (tag) {
			case 0x8: // Input
			case 0x9: // Output
				if (!inside) {
					return false;
				}
				(tag == 0x8 ? input_bits : output_bits) += report_size * report_count;
				break;
			case 0xa: // Collection
				if (depth == 0) {
					// One top-level collection, and it is CTAPHID's.
					if (found || value != 0x01 || !have_usage || last_usage != kCtaphid) {
						return false;
					}
					found = inside = true;
				}
				depth++;
				break;
			case 0xc: // End Collection
				if (depth == 0) {
					return false;
				}
				if (--depth == 0) {
					inside = false;
				}
				break;
			default: return false; // Feature, or a reserved tag
			}
			have_usage = false;
			break;
		case 1: // Global
			switch (tag) {
			case 0x0: page = value; break;
			case 0x7: report_size = value; break;
			case 0x9: report_count = value; break;
			case 0x8: return false; // Report ID
			case 0xa:
			case 0xb: return false; // Push, Pop
			default: break;         // logical/physical extents, units
			}
			break;
		case 2: // Local
			if (tag == 0x0) {
				last_usage = size == 4 ? value : (page << 16) | value;
				have_usage = true;
			}
			break;
		default: return false; // reserved
		}
		if (report_size > kPacketBits || report_count > kPacketBits) {
			return false; // also keeps the sums below from overflowing
		}
	}
	return found && depth == 0 && input_bits == kPacketBits && output_bits == kPacketBits;
}

} // namespace gdp
