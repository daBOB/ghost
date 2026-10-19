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
constexpr uint8_t kCmdKeepalive = 0xbb;
constexpr uint8_t kCmdError = 0xbf;
constexpr uint8_t kKeepaliveUpNeeded = 0x02;
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
// authenticatorCredentialManagement subcommands: 1 to 5 read (metadata,
// then sites and their credentials, a begin and a next for each).
constexpr uint64_t kCmMetadata = 0x01;
constexpr uint64_t kCmEnumerateRpsBegin = 0x02;
constexpr uint64_t kCmEnumerateRpsNext = 0x03;
constexpr uint64_t kCmEnumerateCredentialsBegin = 0x04;
constexpr uint64_t kCmEnumerateCredentialsNext = 0x05;
constexpr uint64_t kCmDeleteCredential = 0x06;
constexpr uint64_t kCmUpdateUser = 0x07;
// authenticatorBioEnrollment subcommands.
constexpr uint64_t kBioEnrollBegin = 0x01;
constexpr uint64_t kBioEnrollCaptureNext = 0x02;
constexpr uint64_t kBioCancelEnrollment = 0x03;
constexpr uint64_t kBioEnumerate = 0x04;
constexpr uint64_t kBioSetFriendlyName = 0x05;
constexpr uint64_t kBioRemove = 0x06;
constexpr uint64_t kBioSensorInfo = 0x07;
// authenticatorConfig subcommands; 0xff, vendorPrototype, is a vendor's.
constexpr uint64_t kConfigEnterpriseAttestation = 0x01;
constexpr uint64_t kConfigToggleAlwaysUv = 0x02;
constexpr uint64_t kConfigSetMinPinLength = 0x03;
constexpr uint8_t kCtap2Ok = 0x00;
constexpr uint8_t kCtap2ErrOperationDenied = 0x27;
constexpr uint8_t kCtap2ErrKeepaliveCancel = 0x2d;
// Credentials remembered from listings, for naming in prompts; more than
// any key holds.
constexpr size_t kMaxRemembered = 512;
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
	bool bytes(std::string *out) {
		uint8_t major;
		uint64_t len;
		if (!head(&major, &len) || major != 2 || len > (uint64_t)(end_ - p_)) {
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

void KeyPolicy::feed(const uint8_t *packet, size_t len, uint64_t now_us, KeyVerdict *verdict) {
	*verdict = KeyVerdict{};
	if (len != kSecurityKeyPacket) {
		return;
	}
	uint32_t cid =
		(uint32_t(packet[0]) << 24) | (uint32_t(packet[1]) << 16) | (uint32_t(packet[2]) << 8) | packet[3];
	KeyPacket copy;
	std::memcpy(copy.data(), packet, kSecurityKeyPacket);
	if (packet[4] & 0x80) {
		// An initialization packet starts over whatever the channel had,
		// a request held for consent included: the host has given up on
		// it. A CANCEL of one is answered as the key would have, and goes
		// no further, since the key never saw what it cancels.
		channels_.erase(cid);
		if (held_.erase(cid)) {
			verdict->withdrawn.push_back(cid);
			if (packet[4] == kCmdCancel) {
				verdict->to_host.push_back(one_byte_reply(cid, kCmdCbor, kCtap2ErrKeepaliveCancel));
				return;
			}
		}
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
			decide(m, now_us, verdict);
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
	decide(done, now_us, verdict);
}

namespace {

// The few fields of a maintenance request's CBOR map that classify it.
struct Fields {
	bool ok = false;
	bool has_sub = false;
	uint64_t sub = 0;
	bool get_modality = false;
	std::string credential_id; // credential management's params, 2: {"id": ...}
	std::string rp_hash;       // credential management's params, 1
};

// Which request a map is, since the same key means different things in
// each: 6 is bio enrolment's getModality flag but ClientPIN's encrypted
// PIN hash, which every PIN-gated sign-in sends.
enum class Shape { kClientPin, kCredentialManagement, kBioEnrollment, kConfig };

Fields read_fields(const std::vector<uint8_t> &data, Shape shape) {
	// The subcommand sits at 2 in ClientPIN's and bio enrolment's maps, at
	// 1 in credential management's and config's.
	const int64_t sub_key = shape == Shape::kClientPin || shape == Shape::kBioEnrollment ? 0x02 : 0x01;
	const bool credential_params = shape == Shape::kCredentialManagement;
	Fields f;
	Cbor cbor(data.data() + 1, data.size() - 1);
	f.ok = cbor.map([&](int64_t k) {
		if (k == sub_key) {
			uint8_t major;
			f.has_sub = cbor.head(&major, &f.sub) && major == 0;
			return f.has_sub;
		}
		if (k == 0x06 && shape == Shape::kBioEnrollment) { // getModality
			return cbor.boolean(&f.get_modality);
		}
		if (credential_params && k == 0x02) {
			return cbor.map([&](int64_t pk) {
				if (pk == 0x01) {
					return cbor.bytes(&f.rp_hash);
				}
				if (pk == 0x02) {
					std::string field;
					return cbor.map(
						[&](int64_t) { return field == "id" ? cbor.bytes(&f.credential_id) : cbor.skip(); },
						&field);
				}
				return cbor.skip();
			});
		}
		return cbor.skip();
	});
	return f;
}

bool is_listing(uint64_t sub) {
	return sub >= kCmMetadata && sub <= kCmEnumerateCredentialsNext;
}

} // namespace

void KeyPolicy::pass(const Message &m, KeyVerdict *verdict) {
	verdict->notice = notice(m, &verdict->request);
	verdict->to_key = m.packets;
}

void KeyPolicy::decide(const Message &m, uint64_t now_us, KeyVerdict *verdict) {
	auto refuse = [&](std::string what, std::string why = {}) {
		verdict->refused = true;
		verdict->refused_what = std::move(what);
		verdict->refused_why = std::move(why);
		verdict->to_host.push_back(one_byte_reply(m.cid, kCmdCbor, kCtap2ErrOperationDenied));
	};
	auto ask = [&](KeyConsent consent, std::string what, bool listing = false, Pending pending = {}) {
		if (!allow_maintenance_) {
			refuse(std::move(what), "Key maintenance is turned off on this computer.");
			return;
		}
		Held h;
		h.message = m;
		h.consent = consent;
		h.listing = listing;
		h.pending = std::move(pending);
		held_[m.cid] = std::move(h);
		verdict->ask = true;
		verdict->held_cid = m.cid;
		verdict->consent = std::move(consent);
	};

	if (!ctaphid_allowed(m.cmd)) {
		char buf[40];
		snprintf(buf, sizeof(buf), "send it CTAPHID command 0x%02x", m.cmd & 0x7f);
		verdict->refused = true;
		verdict->refused_what = buf;
		verdict->refused_why = "The client never passes vendor commands.";
		verdict->to_host.push_back(one_byte_reply(m.cid, kCmdError, kErrInvalidCmd));
		return;
	}
	if (m.cmd != kCmdCbor || m.data.empty()) {
		pass(m, verdict);
		return;
	}
	const uint8_t command = m.data[0];
	switch (command) {
	case kMakeCredential:
	case kGetAssertion:
	case kGetInfo:
	case kGetNextAssertion:
	case kSelection:
	case kLargeBlobs: pass(m, verdict); return;

	case kClientPin: {
		Fields f = read_fields(m.data, Shape::kClientPin);
		if (!f.ok || !f.has_sub) {
			refuse("set or change its PIN");
		} else if (f.sub == kPinSet) {
			ask({KeyConsent::kSetPin, {}, {}}, "set its PIN");
		} else if (f.sub == kPinChange) {
			ask({KeyConsent::kChangePin, {}, {}}, "change its PIN");
		} else {
			pass(m, verdict);
		}
		return;
	}

	case kReset:
		if (attached_us_ == 0 || now_us < attached_us_ || now_us - attached_us_ > kResetWindowUs) {
			refuse("reset it",
				"A key accepts a reset only just after it's plugged in. Unplug it, plug it back in, and reset it "
				"straight away.");
		} else {
			ask({KeyConsent::kReset, {}, {}}, "reset it");
		}
		return;

	case kCredentialManagement:
	case kCredentialManagementPre: {
		Fields f = read_fields(m.data, Shape::kCredentialManagement);
		if (!f.ok || !f.has_sub) {
			refuse("manage its passkeys");
			return;
		}
		if (is_listing(f.sub)) {
			Pending pending{(uint8_t)f.sub, f.rp_hash};
			if (allow_maintenance_ && now_us != 0 && now_us < listing_until_us_) {
				listing_until_us_ = now_us + kListingGrantUs;
				pending_[m.cid] = pending;
				pass(m, verdict);
			} else {
				ask({KeyConsent::kListCredentials, {}, {}}, "list its passkeys", true, pending);
			}
			return;
		}
		if (f.sub == kCmDeleteCredential || f.sub == kCmUpdateUser) {
			KeyConsent c{f.sub == kCmDeleteCredential ? KeyConsent::kDeleteCredential
													  : KeyConsent::kUpdateUser,
				{}, {}};
			auto known = credentials_.find(f.credential_id);
			if (!f.credential_id.empty() && known != credentials_.end()) {
				c.rp_id = known->second.first;
				c.user = known->second.second;
			}
			ask(c, f.sub == kCmDeleteCredential ? "delete a passkey" : "change a passkey's account");
			return;
		}
		refuse("manage its passkeys");
		return;
	}

	case kBioEnrollment:
	case kBioEnrollmentPre: {
		Fields f = read_fields(m.data, Shape::kBioEnrollment);
		if (!f.ok) {
			refuse("enrol fingerprints on it");
			return;
		}
		if (!f.has_sub) {
			if (f.get_modality) {
				pass(m, verdict); // which kind of biometrics: nothing changes
			} else {
				refuse("enrol fingerprints on it");
			}
			return;
		}
		switch (f.sub) {
		case kBioSensorInfo:
		// The samples of an enrolment, and cancelling one: the key takes
		// them only within an enrolment, which began with consent.
		case kBioEnrollCaptureNext:
		case kBioCancelEnrollment: pass(m, verdict); return;
		case kBioEnumerate:
			if (allow_maintenance_ && now_us != 0 && now_us < listing_until_us_) {
				listing_until_us_ = now_us + kListingGrantUs;
				pass(m, verdict);
			} else {
				ask({KeyConsent::kListFingerprints, {}, {}}, "list its fingerprints");
			}
			return;
		case kBioEnrollBegin: ask({KeyConsent::kEnrolFingerprint, {}, {}}, "enrol a fingerprint"); return;
		case kBioSetFriendlyName:
			if (allow_maintenance_ && now_us != 0 && now_us < enrolling_until_us_) {
				pass(m, verdict); // naming the fingerprint just enrolled
			} else {
				ask({KeyConsent::kRenameFingerprint, {}, {}}, "rename a fingerprint");
			}
			return;
		case kBioRemove: ask({KeyConsent::kRemoveFingerprint, {}, {}}, "remove a fingerprint"); return;
		default: refuse("enrol fingerprints on it"); return;
		}
	}

	case kConfig: {
		Fields f = read_fields(m.data, Shape::kConfig);
		if (!f.ok || !f.has_sub) {
			refuse("change its configuration");
		} else if (f.sub == kConfigToggleAlwaysUv) {
			ask({KeyConsent::kAlwaysUv, {}, {}}, "change when it asks for its PIN");
		} else if (f.sub == kConfigSetMinPinLength) {
			ask({KeyConsent::kMinPinLength, {}, {}}, "change its PIN rules");
		} else if (f.sub == kConfigEnterpriseAttestation) {
			ask({KeyConsent::kEnterpriseAttestation, {}, {}}, "turn on enterprise attestation");
		} else {
			refuse("change a vendor setting", "The client never passes vendor commands.");
		}
		return;
	}

	default: {
		char buf[40];
		snprintf(buf, sizeof(buf), "send it command 0x%02x", command);
		refuse(buf, "The client never passes vendor commands.");
		return;
	}
	}
}

void KeyPolicy::approve(uint32_t cid, uint64_t now_us, KeyVerdict *verdict) {
	*verdict = KeyVerdict{};
	auto it = held_.find(cid);
	if (it == held_.end()) {
		return;
	}
	Held h = std::move(it->second);
	held_.erase(it);
	switch (h.consent.kind) {
	case KeyConsent::kListCredentials:
	case KeyConsent::kListFingerprints: listing_until_us_ = now_us + kListingGrantUs; break;
	case KeyConsent::kEnrolFingerprint: enrolling_until_us_ = now_us + kEnrolGrantUs; break;
	default: break;
	}
	if (h.listing) {
		pending_[cid] = h.pending;
	}
	verdict->to_key = h.message.packets;
}

void KeyPolicy::deny(uint32_t cid, KeyVerdict *verdict) {
	*verdict = KeyVerdict{};
	if (held_.erase(cid)) {
		verdict->to_host.push_back(one_byte_reply(cid, kCmdCbor, kCtap2ErrOperationDenied));
	}
}

std::vector<KeyPacket> KeyPolicy::keepalives() const {
	std::vector<KeyPacket> out;
	for (const auto &[cid, h] : held_) {
		out.push_back(one_byte_reply(cid, kCmdKeepalive, kKeepaliveUpNeeded));
	}
	return out;
}

void KeyPolicy::observe_key(const uint8_t *packet, size_t len) {
	if (len != kSecurityKeyPacket) {
		return;
	}
	uint32_t cid =
		(uint32_t(packet[0]) << 24) | (uint32_t(packet[1]) << 16) | (uint32_t(packet[2]) << 8) | packet[3];
	auto pending = pending_.find(cid);
	if (pending == pending_.end()) {
		return;
	}
	if (packet[4] & 0x80) {
		if (packet[4] == kCmdKeepalive) {
			return; // the key is still at it
		}
		replies_.erase(cid);
		if (packet[4] != kCmdCbor) {
			pending_.erase(pending);
			return;
		}
		Message m;
		m.total = (size_t(packet[5]) << 8) | packet[6];
		m.data.assign(packet + 7, packet + 7 + std::min(m.total, kInitData));
		if (m.data.size() < m.total) {
			replies_[cid] = std::move(m);
			return;
		}
		Pending p = pending->second;
		pending_.erase(pending);
		read_reply(cid, p, m.data);
		return;
	}
	auto it = replies_.find(cid);
	if (it == replies_.end() || packet[4] != it->second.next_seq) {
		replies_.erase(cid);
		return;
	}
	Message &m = it->second;
	m.next_seq++;
	size_t take = std::min(m.total - m.data.size(), kContData);
	m.data.insert(m.data.end(), packet + 5, packet + 5 + take);
	if (m.data.size() < m.total) {
		return;
	}
	std::vector<uint8_t> data = std::move(m.data);
	replies_.erase(it);
	Pending p = pending->second;
	pending_.erase(pending);
	read_reply(cid, p, data);
}

// A listing reply: a status byte, then {3: rp {"id": ...}, 4: rpIDHash}
// for a site, or {6: user {"name": ..., "displayName": ...}, 7:
// credentialID {"id": ...}} for one of its credentials.
void KeyPolicy::read_reply(uint32_t, const Pending &pending, const std::vector<uint8_t> &reply) {
	if (reply.empty() || reply[0] != kCtap2Ok) {
		return;
	}
	if (pending.sub == kCmEnumerateCredentialsBegin) {
		auto rp = rp_by_hash_.find(pending.rp_hash);
		listing_rp_ = rp != rp_by_hash_.end() ? rp->second : std::string();
	}
	Cbor cbor(reply.data() + 1, reply.size() - 1);
	std::string rp_id, rp_hash, user_name, display_name, credential_id;
	std::string field;
	cbor.map([&](int64_t k) {
		if (k == 0x03) {
			return cbor.map([&](int64_t) { return field == "id" ? cbor.text(&rp_id) : cbor.skip(); }, &field);
		}
		if (k == 0x04) {
			return cbor.bytes(&rp_hash);
		}
		if (k == 0x06) {
			return cbor.map(
				[&](int64_t) {
					if (field == "name") {
						return cbor.text(&user_name);
					}
					if (field == "displayName") {
						return cbor.text(&display_name);
					}
					return cbor.skip();
				},
				&field);
		}
		if (k == 0x07) {
			return cbor.map([&](int64_t) { return field == "id" ? cbor.bytes(&credential_id) : cbor.skip(); },
				&field);
		}
		return cbor.skip();
	});
	if ((pending.sub == kCmEnumerateRpsBegin || pending.sub == kCmEnumerateRpsNext) && !rp_id.empty() &&
		!rp_hash.empty() && rp_by_hash_.size() < kMaxRemembered) {
		rp_by_hash_[rp_hash] = rp_id;
	}
	if ((pending.sub == kCmEnumerateCredentialsBegin || pending.sub == kCmEnumerateCredentialsNext) &&
		!credential_id.empty() && credentials_.size() < kMaxRemembered) {
		credentials_[credential_id] = {listing_rp_, user_name.empty() ? display_name : user_name};
	}
}

KeyConsentText describe_consent(const KeyConsent &c, const std::string &key_name) {
	const std::string &key = key_name.empty() ? std::string("your security key") : key_name;
	std::string passkey = "one of the passkeys";
	if (!c.rp_id.empty()) {
		passkey = "your passkey for " + c.rp_id + (c.user.empty() ? "" : " (" + c.user + ")");
	}
	switch (c.kind) {
	case KeyConsent::kReset:
		return {"Erase this security key?",
			"The host wants to reset " + key +
				". This erases every passkey on it and its PIN, and can't be undone. If you allow it, touch "
				"the key right away: it accepts a reset only just after it's plugged in.",
			"Erase", "Keep"};
	case KeyConsent::kSetPin:
		return {"Set a PIN on this security key?",
			"The host wants to set a PIN on " + key +
				", which has none. The PIN is hidden from this computer, so allow this only if you typed it "
				"yourself. A PIN you don't know locks you out of the key until it's erased.",
			"Set PIN", "Don't"};
	case KeyConsent::kChangePin:
		return {"Change this security key's PIN?",
			"The host wants to change the PIN on " + key +
				". Allow this only if you're changing it yourself in the session.",
			"Change PIN", "Don't"};
	case KeyConsent::kListCredentials:
		return {"Let the host list your passkeys?",
			"The host wants to list the sites and accounts " + key +
				" has passkeys for. If you allow it, it can keep reading the list for a minute.",
			"List", "Don't"};
	case KeyConsent::kDeleteCredential:
		return {"Delete a passkey?",
			"The host wants to delete " + passkey + " from " + key +
				". Signing in with it stops working, and it can't be undone.",
			"Delete", "Keep"};
	case KeyConsent::kUpdateUser:
		return {"Change a passkey's account name?",
			"The host wants to change the account name stored with " + passkey + " on " + key + ".", "Change",
			"Don't"};
	case KeyConsent::kListFingerprints:
		return {"Let the host list your fingerprints?",
			"The host wants to list the names of the fingerprints enrolled on " + key + ".", "List", "Don't"};
	case KeyConsent::kEnrolFingerprint:
		return {"Add a fingerprint?",
			"The host wants to enrol a fingerprint on " + key +
				". If you allow it, touch the sensor each time the session asks.",
			"Add", "Don't"};
	case KeyConsent::kRemoveFingerprint:
		return {"Remove a fingerprint?",
			"The host wants to remove a fingerprint from " + key +
				". You'd need to enrol it again to use it.",
			"Remove", "Keep"};
	case KeyConsent::kRenameFingerprint:
		return {"Rename a fingerprint?", "The host wants to rename a fingerprint enrolled on " + key + ".",
			"Rename", "Don't"};
	case KeyConsent::kAlwaysUv:
		return {"Change when this key asks for its PIN?",
			"The host wants to switch " + key +
				"'s Always Require Verification setting. On, every use needs the PIN or a fingerprint.",
			"Change", "Don't"};
	case KeyConsent::kMinPinLength:
		return {"Change this key's PIN rules?",
			"The host wants to raise the minimum PIN length on " + key +
				". A longer minimum can't be lowered again without erasing the key, and it may make you "
				"change your PIN.",
			"Change", "Don't"};
	case KeyConsent::kEnterpriseAttestation:
		return {"Let organizations identify this key?",
			"The host wants to turn on enterprise attestation on " + key +
				". Sites your organization set up could then tell this exact key apart from others. Allow "
				"it only if your organization asked you to.",
			"Turn on", "Don't"};
	}
	return {"Allow this?", "The host wants to change " + key + ".", "Allow", "Deny"};
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
