// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "input/security_key.hpp"

#include "gdp/security_key.hpp"
#include "log.hpp"

#include <SDL3/SDL.h>

#include <cstdio>
#include <cstring>

namespace spectre {

namespace {

// How often the reader looks up from a quiet key to see whether it
// should stop.
constexpr int kReadTimeoutMs = 100;
// HID_MAX_DESCRIPTOR_SIZE: room for any descriptor SDL can return.
constexpr size_t kMaxDescriptor = 4096;

std::string utf8(const wchar_t *w) {
	if (!w || !*w) {
		return {};
	}
	char *s = SDL_iconv_wchar_utf8(w);
	if (!s) {
		return {};
	}
	std::string out(s);
	SDL_free(s);
	return out;
}

// Linux only: whether the hidraw node at `path` is one ghostseat made
// (HID_PHYS=ghost/..., host/ghostseat/src/devices.rs), as
// stream_session.cpp's is_ghost_virtual_pad() checks for controllers.
bool is_ghost_virtual_key(const std::string &path) {
#ifdef __linux__
	const char *name = strrchr(path.c_str(), '/');
	if (!name || strncmp(name + 1, "hidraw", 6) != 0) {
		return false;
	}
	std::string uevent = std::string("/sys/class/hidraw/") + (name + 1) + "/device/uevent";
	FILE *f = fopen(uevent.c_str(), "r");
	if (!f) {
		return false;
	}
	char line[256];
	bool ghost = false;
	while (!ghost && fgets(line, sizeof(line), f)) {
		ghost = strncmp(line, "HID_PHYS=ghost/", 15) == 0;
	}
	fclose(f);
	return ghost;
#else
	(void)path;
	return false;
#endif
}

} // namespace

std::vector<SecurityKey::Identity> SecurityKey::find() {
	std::vector<Identity> keys;
	// SDL lists only game controllers unless told otherwise. The hint only
	// filters what SDL_hid_enumerate() returns: SDL's own controller
	// drivers check each device themselves.
	SDL_SetHint(SDL_HINT_HIDAPI_ENUMERATE_ONLY_CONTROLLERS, "0");
	SDL_hid_device_info *list = SDL_hid_enumerate(0, 0);
	for (SDL_hid_device_info *info = list; info; info = info->next) {
		if (info->usage_page != gdp::kFidoUsagePage || info->usage != gdp::kFidoUsageCtaphid ||
			info->bus_type != SDL_HID_API_BUS_USB || !info->path) {
			continue;
		}
		if (is_ghost_virtual_key(info->path)) {
			continue;
		}
		Identity id;
		id.path = info->path;
		id.vendor_id = info->vendor_id;
		id.product_id = info->product_id;
		id.version = info->release_number;
		// Named as RawController names a USB device: "manufacturer
		// product" unless the product already starts with it.
		std::string product = utf8(info->product_string);
		std::string manufacturer = utf8(info->manufacturer_string);
		id.name = product;
		if (!manufacturer.empty() && product.rfind(manufacturer, 0) != 0) {
			id.name = manufacturer + (product.empty() ? "" : " " + product);
		}
		if (id.name.empty()) {
			id.name = "Security key";
		}
		if (id.name.size() > gdp::kMaxSecurityKeyName) {
			id.name.resize(gdp::kMaxSecurityKeyName);
		}
		keys.push_back(std::move(id));
	}
	SDL_hid_free_enumeration(list);
	return keys;
}

std::unique_ptr<SecurityKey> SecurityKey::open(const Identity &id, std::string *why) {
	SDL_hid_device *dev = SDL_hid_open_path(id.path.c_str());
	if (!dev) {
		*why = std::string("can't open ") + id.path + ": " + SDL_GetError();
		return nullptr;
	}
	std::vector<uint8_t> rd(kMaxDescriptor);
	int len = SDL_hid_get_report_descriptor(dev, rd.data(), rd.size());
	if (len <= 0) {
		*why = std::string("can't read its report descriptor: ") + SDL_GetError();
		SDL_hid_close(dev);
		return nullptr;
	}
	if (!gdp::is_ctaphid_descriptor(rd.data(), (size_t)len)) {
		*why = "its report descriptor isn't a plain CTAPHID one (64-byte reports, no report IDs)";
		SDL_hid_close(dev);
		return nullptr;
	}
	return std::unique_ptr<SecurityKey>(new SecurityKey(dev, id));
}

SecurityKey::SecurityKey(SDL_hid_device *dev, Identity identity)
	: dev_(dev), identity_(std::move(identity)) {}

SecurityKey::~SecurityKey() {
	{
		std::lock_guard<std::mutex> lock(mutex_);
		stopping_ = true;
	}
	cv_.notify_all();
	if (writer_.joinable()) {
		writer_.join();
	}
	if (reader_.joinable()) {
		reader_.join(); // at most kReadTimeoutMs
	}
	SDL_hid_close(dev_);
}

void SecurityKey::start(InputFn on_input) {
	on_input_ = std::move(on_input);
	reader_ = std::thread([this] { read_loop(); });
	writer_ = std::thread([this] { write_loop(); });
}

void SecurityKey::output(const std::string &packet) {
	if (packet.size() != gdp::kSecurityKeyPacket) {
		return;
	}
	{
		std::lock_guard<std::mutex> lock(mutex_);
		queue_.push_back(packet);
	}
	cv_.notify_one();
}

void SecurityKey::read_loop() {
	uint8_t buf[gdp::kSecurityKeyPacket];
	bool complained = false;
	for (;;) {
		{
			std::lock_guard<std::mutex> lock(mutex_);
			if (stopping_) {
				return;
			}
		}
		int n = SDL_hid_read_timeout(dev_, buf, sizeof(buf), kReadTimeoutMs);
		if (n < 0) {
			// Unplugged, most likely: the next find() misses it and
			// StreamSession tears this down.
			SLOG_INFO("spectre: security key \"%s\": read failed (%s), reader stopping",
				identity_.name.c_str(), SDL_GetError());
			return;
		}
		if (n == (int)sizeof(buf)) {
			on_input_(buf, sizeof(buf));
		} else if (n > 0 && !complained) {
			complained = true;
			SLOG_ERROR("spectre: security key \"%s\": dropping a %d-byte report (a packet is %zu)",
				identity_.name.c_str(), n, sizeof(buf));
		}
	}
}

void SecurityKey::write_loop() {
	for (;;) {
		std::string packet;
		{
			std::unique_lock<std::mutex> lock(mutex_);
			cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
			if (stopping_) {
				return;
			}
			packet = std::move(queue_.front());
			queue_.pop_front();
		}
		// Report ID 0 first, hidapi's convention for an unnumbered report.
		unsigned char report[1 + gdp::kSecurityKeyPacket] = {0};
		std::memcpy(report + 1, packet.data(), gdp::kSecurityKeyPacket);
		if (SDL_hid_write(dev_, report, sizeof(report)) < 0) {
			SLOG_ERROR("spectre: security key \"%s\": write failed: %s", identity_.name.c_str(),
				SDL_GetError());
		}
	}
}

} // namespace spectre
