// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "session/security_keys.hpp"

#include "control.pb.h"
#include "session.pb.h"
#include "session/seat_client.hpp"
#include "session/uhid_codec.hpp"

#include <unistd.h>
#include <wayland-server-core.h>

#include <cerrno>
#include <cstring>

#include "util/log.hpp"

namespace wraith {

SecurityKeys::SecurityKeys(std::string control_socket, struct wl_event_loop *loop, Send send)
	: control_socket_(std::move(control_socket)), loop_(loop), send_(std::move(send)) {
	for (uint32_t i = 0; i < gdp::kMaxSecurityKeys; i++) {
		slots_[i].owner = this;
		slots_[i].index = i;
	}
}

SecurityKeys::~SecurityKeys() {
	disconnect_all();
}

void SecurityKeys::connect(const gdp::session::SecurityKeyConnect &c) {
	uint32_t index = c.key_index();
	if (index >= gdp::kMaxSecurityKeys) {
		WLOG_ERROR("key: client used slot %u, max is %u", index, gdp::kMaxSecurityKeys - 1);
		return;
	}
	disconnect(index);
	if (c.name().size() > gdp::kMaxSecurityKeyName) {
		reject(index, "name too long");
		return;
	}
	// Only the IDs: ghostseat sets the bus and the descriptor (§8.7).
	ghost::control::HidIdentity identity;
	identity.set_vendor_id(c.vendor_id());
	identity.set_product_id(c.product_id());
	identity.set_version(c.version());

	Slot &slot = slots_[index];
	std::string node, error;
	int conn = -1;
	slot.verdict_reader = gdp::FrameReader{};
	int fd = SeatClient::create_hid_device(control_socket_, ghost::control::CreateDevice::KIND_SECURITY_KEY,
		index, c.name(), identity, &node, &conn, &slot.verdict_reader, &error);
	if (fd < 0) {
		WLOG_ERROR("key: slot %u (\"%s\" %04x:%04x): ghostseat could not create a device: %s", index,
			c.name().c_str(), c.vendor_id(), c.product_id(), error.c_str());
		reject(index, error);
		return;
	}
	slot.fd = fd;
	slot.verdict_fd = conn;
	slot.verified = false;
	slot.write_failed = false;
	slot.name = c.name();
	slot.fd_source.reset(wl_event_loop_add_fd(loop_, fd, WL_EVENT_READABLE, on_device_event, &slot));
	slot.verdict_source.reset(wl_event_loop_add_fd(loop_, conn, WL_EVENT_READABLE, on_verdict, &slot));
	WLOG_INFO("key: slot %u (\"%s\" %04x:%04x) is %s, waiting for its driver", index, c.name().c_str(),
		c.vendor_id(), c.product_id(), node.c_str());
	// The verdict may have come with DeviceCreated, already read.
	drain_verdict(slot);
}

void SecurityKeys::disconnect(uint32_t index) {
	if (index >= gdp::kMaxSecurityKeys) {
		return;
	}
	Slot &slot = slots_[index];
	close_verdict(slot);
	if (slot.fd < 0) {
		return;
	}
	slot.fd_source.reset();
	// Closing wraith's end destroys the device: the browser holding its
	// hidraw node sees the key unplugged.
	close(slot.fd);
	slot.fd = -1;
	slot.verified = false;
	WLOG_INFO("key: slot %u removed", index);
}

void SecurityKeys::disconnect_all() {
	for (uint32_t i = 0; i < gdp::kMaxSecurityKeys; i++) {
		disconnect(i);
	}
}

bool SecurityKeys::connected(uint32_t index) const {
	return index < gdp::kMaxSecurityKeys && slots_[index].fd >= 0;
}

void SecurityKeys::input(const gdp::session::SecurityKeyInput &in) {
	if (!connected(in.key_index())) {
		return;
	}
	Slot &slot = slots_[in.key_index()];
	// gdp-spec.md §8.7: exactly one packet, and nothing until ghostseat has
	// checked what the driver made of the device (its relay drops it too).
	const std::string &data = in.data();
	if (!slot.verified || data.size() != gdp::kSecurityKeyPacket) {
		return;
	}
	write_event(slot, uhid::input2(reinterpret_cast<const uint8_t *>(data.data()), data.size()));
}

int SecurityKeys::on_device_event(int, uint32_t, void *data) {
	auto *slot = static_cast<Slot *>(data);
	slot->owner->read_device(*slot);
	return 0;
}

void SecurityKeys::read_device(Slot &slot) {
	// One event per read() (one packet from ghostseat's relay); the fd is
	// non-blocking, so the loop ends at EAGAIN.
	uint8_t buf[uhid::kEventSize];
	while (slot.fd >= 0) {
		ssize_t n = read(slot.fd, buf, sizeof(buf));
		if (n < 0) {
			if (errno != EAGAIN && errno != EINTR) {
				WLOG_ERROR("key: slot %u: read failed: %s", slot.index, strerror(errno));
				slot.fd_source.reset();
			}
			if (errno != EINTR) {
				return;
			}
			continue;
		}
		if (n == 0) {
			return;
		}
		handle_device_event(slot, buf, (size_t)n);
	}
}

void SecurityKeys::handle_device_event(Slot &slot, const uint8_t *buf, size_t len) {
	uhid::Event ev;
	if (!uhid::parse(buf, len, &ev)) {
		WLOG_ERROR("key: slot %u: short or malformed uhid event (%zu bytes)", slot.index, len);
		return;
	}
	switch (ev.type) {
	case uhid::kOutput: break;
	case uhid::kOpen: WLOG_DEBUG("key: slot %u: opened", slot.index); return;
	case uhid::kClose: WLOG_DEBUG("key: slot %u: closed", slot.index); return;
	default: return;
	}
	uint8_t packet[gdp::kSecurityKeyPacket];
	if (!uhid::fido_packet(ev, packet)) {
		WLOG_ERROR("key: slot %u: dropping an output report of %zu bytes that isn't a CTAPHID packet",
			slot.index, ev.size);
		return;
	}
	gdp::session::HostInputEnvelope env;
	auto *out = env.mutable_security_key_output();
	out->set_key_index(slot.index);
	out->set_data(packet, sizeof(packet));
	send_(env);
}

void SecurityKeys::write_event(Slot &slot, const std::vector<uint8_t> &ev) {
	if (slot.fd < 0) {
		return;
	}
	if (write(slot.fd, ev.data(), ev.size()) != (ssize_t)ev.size() && !slot.write_failed) {
		slot.write_failed = true;
		WLOG_ERROR("key: slot %u: write failed: %s", slot.index, strerror(errno));
	}
}

int SecurityKeys::on_verdict(int, uint32_t, void *data) {
	auto *slot = static_cast<Slot *>(data);
	slot->owner->read_verdict(*slot);
	return 0;
}

void SecurityKeys::read_verdict(Slot &slot) {
	uint8_t buf[4096];
	ssize_t n = read(slot.verdict_fd, buf, sizeof(buf));
	if (n < 0 && (errno == EAGAIN || errno == EINTR)) {
		return;
	}
	if (n <= 0) {
		reject(slot.index, "ghostseat closed the connection without a verdict");
		return;
	}
	slot.verdict_reader.feed(buf, (size_t)n);
	drain_verdict(slot);
}

void SecurityKeys::drain_verdict(Slot &slot) {
	ghost::control::ControlEnvelope env;
	for (;;) {
		gdp::FrameReader::Result r = slot.verdict_reader.drain(&env);
		if (r == gdp::FrameReader::Result::kIncomplete) {
			return;
		}
		uint32_t index = slot.index;
		if (r != gdp::FrameReader::Result::kOk) {
			reject(index, "malformed verdict from ghostseat");
			return;
		}
		if (env.has_device_verified()) {
			slot.verified = true;
			close_verdict(slot);
			WLOG_INFO("key: slot %u (\"%s\"): driver %s bound, packets flowing", index, slot.name.c_str(),
				env.device_verified().driver().c_str());
			return;
		}
		if (env.has_error()) {
			WLOG_ERROR("key: slot %u (\"%s\"): %s", index, slot.name.c_str(), env.error().message().c_str());
			reject(index, env.error().message());
			return;
		}
		// Anything else is ghostseat's mistake; keep waiting for the verdict.
	}
}

void SecurityKeys::close_verdict(Slot &slot) {
	slot.verdict_source.reset();
	if (slot.verdict_fd >= 0) {
		close(slot.verdict_fd);
		slot.verdict_fd = -1;
	}
}

void SecurityKeys::reject(uint32_t index, const std::string &reason) {
	disconnect(index);
	gdp::session::HostInputEnvelope env;
	auto *rejected = env.mutable_security_key_rejected();
	rejected->set_key_index(index);
	rejected->set_reason(reason);
	send_(env);
}

} // namespace wraith
