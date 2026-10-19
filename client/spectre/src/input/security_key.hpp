// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// One security key forwarded to the host (gdp-spec.md §8.7,
// docs/adr/0015): its FIDO HID interface, opened through SDL's HID API,
// whose CTAPHID packets are relayed both ways unread. Keys aren't
// joysticks, so nothing announces them: StreamSession lists them with
// find() whenever SDL's HID device count changes.
//
// Two threads per key, as for a raw controller (input/raw_controller.hpp):
// the reader blocks in SDL_hid_read_timeout() and hands each packet to
// `on_input`; the writer performs the host's packets, a write each. The
// destructor stops and joins both before closing the device.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct SDL_hid_device;

namespace spectre {

class SecurityKey {
public:
	// What SecurityKeyConnect carries, and where the key is.
	struct Identity {
		std::string path; // SDL's HID path: how find()'s lists are compared
		std::string name;
		uint32_t vendor_id = 0;
		uint32_t product_id = 0;
		uint32_t version = 0;
	};

	// Every USB HID interface on the FIDO page's CTAPHID usage, as SDL
	// lists them -- leaving out, on Linux, ghost's own virtual keys, which
	// a spectre on the host would otherwise forward back into the session
	// they came from.
	static std::vector<Identity> find();

	// Opens the key at `id.path`, checking that its report descriptor is
	// one gdp-spec.md §8.7 lets a client forward. nullptr, with `*why`
	// set, otherwise (Windows refuses to open a FIDO interface to a
	// process that isn't elevated).
	static std::unique_ptr<SecurityKey> open(const Identity &id, std::string *why);
	~SecurityKey();
	SecurityKey(const SecurityKey &) = delete;
	SecurityKey &operator=(const SecurityKey &) = delete;

	const Identity &identity() const { return identity_; }

	using InputFn = std::function<void(const uint8_t *packet, size_t len)>;
	// Starts both threads. Call once.
	void start(InputFn on_input);
	// One packet from the host, queued for the writer.
	void output(const std::string &packet);

private:
	SecurityKey(SDL_hid_device *dev, Identity identity);
	void read_loop();
	void write_loop();

	SDL_hid_device *dev_;
	Identity identity_;
	InputFn on_input_;
	std::thread reader_;
	std::thread writer_;
	std::mutex mutex_;
	std::condition_variable cv_;
	std::deque<std::string> queue_;
	bool stopping_ = false;
};

} // namespace spectre
