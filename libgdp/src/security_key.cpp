// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/security_key.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

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

namespace {

// CTAPHID (FIDO CTAP 2.1 §11.2.4): an initialization packet is the
// channel, a command with its top bit set and a big-endian length, then
// 57 bytes; each continuation packet is the channel, a sequence number
// below 0x80, then 59 bytes. A message is at most 57 + 128 * 59 bytes.
constexpr uint8_t kCmdPing = 0x81;
constexpr uint8_t kCmdMsg = 0x83; // U2F APDU
constexpr uint8_t kCmdLock = 0x84;
constexpr uint8_t kCmdInit = 0x86;
constexpr uint8_t kCmdWink = 0x88;
constexpr uint8_t kCmdCbor = 0x90; // CTAP2
constexpr uint8_t kCmdCancel = 0x91;
constexpr uint8_t kCmdError = 0xbf;
constexpr uint8_t kErrInvalidCmd = 0x01;
constexpr uint8_t kErrInvalidLen = 0x03;
constexpr uint8_t kErrInvalidSeq = 0x04;
constexpr size_t kInitData = 57;
constexpr size_t kContData = 59;
constexpr size_t kMaxMessage = kInitData + 128 * kContData;
// Channels being reassembled at once; a browser uses one or two.
constexpr size_t kMaxChannels = 8;

// CTAP2 commands (CTAP 2.1 §6) a session may send: what a sign-in uses.
constexpr uint8_t kMakeCredential = 0x01;
constexpr uint8_t kGetAssertion = 0x02;
constexpr uint8_t kGetInfo = 0x04;
constexpr uint8_t kClientPin = 0x06;
constexpr uint8_t kReset = 0x07;
constexpr uint8_t kGetNextAssertion = 0x08;
constexpr uint8_t kBioEnrollment = 0x09;
constexpr uint8_t kCredentialManagement = 0x0a;
constexpr uint8_t kSelection = 0x0b;
constexpr uint8_t kLargeBlobs = 0x0c;
constexpr uint8_t kConfig = 0x0d;
constexpr uint8_t kBioEnrollmentPre = 0x40;
constexpr uint8_t kCredentialManagementPre = 0x41;
// authenticatorClientPIN subcommands: setting and changing the PIN are
// maintenance; the rest fetch what a PIN-gated sign-in needs.
constexpr uint64_t kPinSet = 0x03;
constexpr uint64_t kPinChange = 0x04;
constexpr uint8_t kCtap2ErrOperationDenied = 0x27;
// U2F APDU instructions.
constexpr uint8_t kU2fRegister = 0x01;
constexpr uint8_t kU2fAuthenticate = 0x02;
// U2F authenticate's control byte that only checks a key handle, with no
// touch.
constexpr uint8_t kU2fCheckOnly = 0x07;

bool ctaphid_allowed(uint8_t cmd) {
	switch (cmd) {
	case kCmdPing:
	case kCmdMsg:
	case kCmdLock:
	case kCmdInit:
	case kCmdWink:
	case kCmdCbor:
	case kCmdCancel: return true;
	default: return false; // KEEPALIVE and ERROR go the other way; vendor commands aren't relayed
	}
}

// What the host tried, for the user, or "" for an allowed command.
std::string refused_ctap2(uint8_t command) {
	switch (command) {
	case kMakeCredential:
	case kGetAssertion:
	case kGetInfo:
	case kClientPin:
	case kGetNextAssertion:
	case kSelection:
	case kLargeBlobs: return {};
	case kReset: return "reset it";
	case kBioEnrollment:
	case kBioEnrollmentPre: return "enrol fingerprints on it";
	case kCredentialManagement:
	case kCredentialManagementPre: return "manage its credentials";
	case kConfig: return "change its configuration";
	default: {
		char buf[40];
		snprintf(buf, sizeof(buf), "send it command 0x%02x", command);
		return buf;
	}
	}
}

KeyPacket one_byte_reply(uint32_t cid, uint8_t cmd, uint8_t value) {
	KeyPacket p{};
	p[0] = uint8_t(cid >> 24), p[1] = uint8_t(cid >> 16), p[2] = uint8_t(cid >> 8), p[3] = uint8_t(cid);
	p[4] = cmd, p[5] = 0, p[6] = 1, p[7] = value;
	return p;
}

// Just enough CBOR (RFC 8949) to find a few keys in a CTAP request's map
// and step over everything else.
class Cbor {
public:
	Cbor(const uint8_t *p, size_t n) : p_(p), end_(p + n) {}
	bool head(uint8_t *major, uint64_t *value) {
		if (p_ >= end_) {
			return false;
		}
		uint8_t b = *p_++;
		*major = b >> 5;
		uint8_t info = b & 0x1f;
		if (info < 24) {
			*value = info;
			return true;
		}
		if (info > 27) {
			return false; // indefinite lengths: CTAP's canonical CBOR has none
		}
		size_t bytes = size_t(1) << (info - 24);
		if ((size_t)(end_ - p_) < bytes) {
			return false;
		}
		*value = 0;
		for (size_t i = 0; i < bytes; i++) {
			*value = (*value << 8) | *p_++;
		}
		return true;
	}
	bool text(std::string *out) {
		uint8_t major;
		uint64_t len;
		if (!head(&major, &len) || major != 3 || len > (uint64_t)(end_ - p_)) {
			return false;
		}
		out->assign(reinterpret_cast<const char *>(p_), (size_t)len);
		p_ += len;
		return true;
	}
	bool skip(int depth = 0) {
		uint8_t major;
		uint64_t value;
		if (depth > 8 || !head(&major, &value)) {
			return false;
		}
		switch (major) {
		case 2:
		case 3:
			if (value > (uint64_t)(end_ - p_)) {
				return false;
			}
			p_ += value;
			return true;
		case 4:
		case 5:
			for (uint64_t i = 0; i < value * (major == 5 ? 2 : 1); i++) {
				if (!skip(depth + 1)) {
					return false;
				}
			}
			return true;
		case 6: return skip(depth + 1);
		default: return true; // integers, simple values, floats: the head was all
		}
	}
	// A map's entries: `on_entry(key)` reads or skips the value and says
	// whether to go on. Integer keys, as CTAP's requests use; a text key
	// (inside rp, options) is passed as -1 with the text in *text_key.
	template <typename F> bool map(F &&on_entry, std::string *text_key = nullptr) {
		uint8_t major;
		uint64_t count;
		if (!head(&major, &count) || major != 5) {
			return false;
		}
		for (uint64_t i = 0; i < count; i++) {
			uint8_t key_major;
			uint64_t key;
			const uint8_t *at = p_;
			if (!head(&key_major, &key)) {
				return false;
			}
			int64_t k = (int64_t)key;
			if (key_major == 3 && text_key) {
				p_ = at;
				if (!text(text_key)) {
					return false;
				}
				k = -1;
			} else if (key_major != 0) {
				return false;
			}
			if (!on_entry(k)) {
				return false;
			}
		}
		return true;
	}
	bool boolean(bool *out) {
		if (p_ >= end_ || (*p_ != 0xf4 && *p_ != 0xf5)) {
			return false;
		}
		*out = *p_++ == 0xf5;
		return true;
	}

private:
	const uint8_t *p_;
	const uint8_t *end_;
};

} // namespace

void KeyPolicy::feed(const uint8_t *packet, size_t len, KeyVerdict *verdict) {
	*verdict = KeyVerdict{};
	if (len != kSecurityKeyPacket) {
		return;
	}
	uint32_t cid =
		(uint32_t(packet[0]) << 24) | (uint32_t(packet[1]) << 16) | (uint32_t(packet[2]) << 8) | packet[3];
	KeyPacket copy;
	std::memcpy(copy.data(), packet, kSecurityKeyPacket);
	if (packet[4] & 0x80) {
		// An initialization packet starts over whatever the channel had.
		channels_.erase(cid);
		Message m;
		m.cid = cid;
		m.cmd = packet[4];
		m.total = (size_t(packet[5]) << 8) | packet[6];
		if (m.total > kMaxMessage) {
			verdict->to_host.push_back(one_byte_reply(cid, kCmdError, kErrInvalidLen));
			return;
		}
		m.data.assign(packet + 7, packet + 7 + std::min(m.total, kInitData));
		m.packets.push_back(copy);
		if (m.data.size() == m.total) {
			decide(m, verdict);
			return;
		}
		if (channels_.size() >= kMaxChannels) {
			channels_.erase(channels_.begin());
		}
		channels_[cid] = std::move(m);
		return;
	}
	auto it = channels_.find(cid);
	if (it == channels_.end()) {
		return; // a continuation with no message: a key ignores it too
	}
	Message &m = it->second;
	if (packet[4] != m.next_seq) {
		channels_.erase(it);
		verdict->to_host.push_back(one_byte_reply(cid, kCmdError, kErrInvalidSeq));
		return;
	}
	m.next_seq++;
	size_t take = std::min(m.total - m.data.size(), kContData);
	m.data.insert(m.data.end(), packet + 5, packet + 5 + take);
	m.packets.push_back(copy);
	if (m.data.size() < m.total) {
		return;
	}
	Message done = std::move(m);
	channels_.erase(it);
	decide(done, verdict);
}

void KeyPolicy::decide(const Message &m, KeyVerdict *verdict) const {
	if (!ctaphid_allowed(m.cmd)) {
		char buf[40];
		snprintf(buf, sizeof(buf), "send it CTAPHID command 0x%02x", m.cmd & 0x7f);
		verdict->refused = true;
		verdict->refused_what = buf;
		verdict->to_host.push_back(one_byte_reply(m.cid, kCmdError, kErrInvalidCmd));
		return;
	}
	if (m.cmd == kCmdCbor && !m.data.empty()) {
		uint8_t command = m.data[0];
		std::string what = refused_ctap2(command);
		if (command == kClientPin) {
			// {1: pinUvAuthProtocol, 2: subCommand, ...}: refused unless the
			// subcommand is readable and not a PIN change.
			Cbor cbor(m.data.data() + 1, m.data.size() - 1);
			uint64_t sub = 0;
			bool found = false;
			bool ok = cbor.map([&](int64_t k) {
				if (k == 0x02) {
					uint8_t major;
					found = cbor.head(&major, &sub) && major == 0;
					return found;
				}
				return cbor.skip();
			});
			if (!ok || !found || sub == kPinSet || sub == kPinChange) {
				what = "set or change its PIN";
			}
		}
		if (!what.empty()) {
			verdict->refused = true;
			verdict->refused_what = what;
			verdict->to_host.push_back(one_byte_reply(m.cid, kCmdCbor, kCtap2ErrOperationDenied));
			return;
		}
	}
	verdict->notice = notice(m, &verdict->request);
	verdict->to_key = m.packets;
}

bool KeyPolicy::notice(const Message &m, KeyRequest *request) const {
	if (m.data.empty()) {
		return false;
	}
	if (m.cmd == kCmdMsg) {
		// An APDU: CLA INS P1 ... ; authenticate's P1 says whether it wants
		// the user present.
		if (m.data.size() < 3) {
			return false;
		}
		uint8_t ins = m.data[1];
		if (ins == kU2fRegister || (ins == kU2fAuthenticate && m.data[2] != kU2fCheckOnly)) {
			*request = KeyRequest{KeyRequest::kU2f, {}};
			return true;
		}
		return false;
	}
	if (m.cmd != kCmdCbor) {
		return false;
	}
	uint8_t command = m.data[0];
	if (command == kSelection) {
		*request = KeyRequest{KeyRequest::kSelect, {}};
		return true;
	}
	if (command != kMakeCredential && command != kGetAssertion) {
		return false;
	}
	Cbor cbor(m.data.data() + 1, m.data.size() - 1);
	std::string rp_id;
	bool user_presence = true;
	std::string key;
	bool ok = cbor.map([&](int64_t k) {
		if (command == kMakeCredential && k == 0x02) {
			// rp: {"id": text, "name": text, ...}
			std::string field;
			return cbor.map(
				[&](int64_t) {
					if (field == "id") {
						return cbor.text(&rp_id);
					}
					return cbor.skip();
				},
				&field);
		}
		if (command == kGetAssertion && k == 0x01) {
			return cbor.text(&rp_id);
		}
		if (command == kGetAssertion && k == 0x05) {
			// options: {"up": bool, "uv": bool}
			std::string field;
			return cbor.map(
				[&](int64_t) {
					if (field == "up") {
						return cbor.boolean(&user_presence);
					}
					return cbor.skip();
				},
				&field);
		}
		return cbor.skip();
	});
	if (!ok || rp_id.empty() || !user_presence) {
		return false;
	}
	// Chrome and Firefox ask the user to pick a key by registering with a
	// placeholder relying party no site has.
	if (command == kMakeCredential && rp_id == ".dummy") {
		*request = KeyRequest{KeyRequest::kSelect, {}};
		return true;
	}
	*request = KeyRequest{command == kMakeCredential ? KeyRequest::kRegister : KeyRequest::kSignIn, rp_id};
	return true;
}

} // namespace gdp
