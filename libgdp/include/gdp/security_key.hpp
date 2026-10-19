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

} // namespace gdp
