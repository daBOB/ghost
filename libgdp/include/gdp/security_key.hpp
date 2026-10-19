// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// Security keys (gdp-spec.md §8.7, docs/adr/0015): the "security-key"
// capability and its limits. A key is relayed as CTAPHID packets, which
// neither end reads beyond their length.
#pragma once

#include <cstddef>
#include <cstdint>

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

} // namespace gdp
