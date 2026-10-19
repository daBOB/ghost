// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Security keys (gdp-spec.md §8.7, docs/adr/0015): a FIDO key at the
// client presented in the session as a uhid FIDO device, which the
// session's browsers find through its hidraw node like a key plugged into
// the host. ghostseat creates the device with its own descriptor
// (seat_client.hpp's create_hid_device, KIND_SECURITY_KEY) and answers the
// driver's report requests itself; this class relays CTAPHID packets
// between ghostseat's fd and the client, without reading them:
//
// - SecurityKeyInput -> UHID_INPUT2, held back until DeviceVerified;
// - UHID_OUTPUT -> SecurityKeyOutput, the report ID taken off.
//
// ghostseat's verdict arrives on the CreateDevice connection as for a raw
// controller (session/raw_controllers.hpp); a ControlError there or a
// failed create becomes SecurityKeyRejected.
//
// Per-client, like RawControllers: the session disconnects every slot
// when the client goes away, so a key is never left plugged in for the
// next client, or for nobody.
#pragma once

#include "gdp/framing.hpp"
#include "gdp/security_key.hpp"
#include "util/event_source.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

struct wl_event_loop;

namespace gdp::session {
class SecurityKeyConnect;
class SecurityKeyInput;
class HostInputEnvelope;
} // namespace gdp::session

namespace wraith {

class SecurityKeys {
public:
	using Send = std::function<void(const gdp::session::HostInputEnvelope &)>;

	// `control_socket` is the -G control socket path. `send` puts a
	// message on the attached client's input stream.
	SecurityKeys(std::string control_socket, struct wl_event_loop *loop, Send send);
	~SecurityKeys();
	SecurityKeys(const SecurityKeys &) = delete;
	SecurityKeys &operator=(const SecurityKeys &) = delete;

	// Creates the device for the connect's slot, replacing what was
	// there. On failure the slot stays empty and the client gets
	// SecurityKeyRejected.
	void connect(const gdp::session::SecurityKeyConnect &connect);
	// Destroys the slot's device; no-op for an empty slot.
	void disconnect(uint32_t index);
	void disconnect_all();
	bool connected(uint32_t index) const;

	void input(const gdp::session::SecurityKeyInput &input);

private:
	struct Slot {
		SecurityKeys *owner = nullptr;
		uint32_t index = 0;
		int fd = -1; // ghostseat's relay to the device; close() destroys it
		EventSource fd_source;
		int verdict_fd = -1; // the CreateDevice connection, until ghostseat's verdict
		EventSource verdict_source;
		gdp::FrameReader verdict_reader;
		bool verified = false;
		bool write_failed = false; // logged once per device, not per packet
		std::string name;
	};

	static int on_device_event(int fd, uint32_t mask, void *data);
	static int on_verdict(int fd, uint32_t mask, void *data);
	void read_device(Slot &slot);
	void handle_device_event(Slot &slot, const uint8_t *buf, size_t len);
	void read_verdict(Slot &slot);
	void drain_verdict(Slot &slot);
	void close_verdict(Slot &slot);
	void reject(uint32_t index, const std::string &reason);
	void write_event(Slot &slot, const std::vector<uint8_t> &ev);

	std::string control_socket_;
	struct wl_event_loop *loop_;
	Send send_;
	Slot slots_[gdp::kMaxSecurityKeys];
};

} // namespace wraith
