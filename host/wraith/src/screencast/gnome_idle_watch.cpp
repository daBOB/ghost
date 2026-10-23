// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "screencast/gnome_idle_watch.hpp"

#include "screencast/sdbus_util.hpp"

#include <systemd/sd-bus.h>

#include "util/log.hpp"

#include <cstdlib>
#include <cstring>

namespace wraith {

namespace {

constexpr const char *kSmService = "org.gnome.SessionManager";
constexpr const char *kSmPath = "/org/gnome/SessionManager";
constexpr const char *kSmIface = "org.gnome.SessionManager";
constexpr const char *kInhibitedActions = "InhibitedActions";
constexpr uint32_t kInhibitIdle = 8; // GSM_INHIBITOR_FLAG_IDLE

} // namespace

struct GnomeIdleWatch::Impl {
	GnomeIdleWatch *owner = nullptr;
	sd_bus *bus = nullptr;
	sd_bus_slot *changed_slot = nullptr;

	bool read(uint32_t *actions) {
		sd_bus_error error = SD_BUS_ERROR_NULL;
		int r = sd_bus_get_property_trivial(bus, kSmService, kSmPath, kSmIface, kInhibitedActions, &error, 'u',
			actions);
		if (r < 0) {
			WLOG_INFO("idle: reading gnome-session's InhibitedActions failed (%s)", sdbus_error_text(error, r));
		}
		sd_bus_error_free(&error);
		return r >= 0;
	}

	// Null owner: a change that came in during create()'s read, which
	// the read's own value covers.
	void apply(uint32_t actions) {
		if (owner) {
			owner->set_inhibited((actions & kInhibitIdle) != 0);
		}
	}

	// PropertiesChanged(s interface, a{sv} changed, as invalidated).
	static int on_properties_changed(sd_bus_message *m, void *data, sd_bus_error *) {
		auto *i = static_cast<Impl *>(data);
		const char *iface = nullptr;
		if (sd_bus_message_read(m, "s", &iface) < 0 || !iface || strcmp(iface, kSmIface) != 0) {
			return 0;
		}
		if (sd_bus_message_enter_container(m, 'a', "{sv}") < 0) {
			return 0;
		}
		while (sd_bus_message_enter_container(m, 'e', "sv") > 0) {
			const char *name = nullptr;
			sd_bus_message_read(m, "s", &name);
			uint32_t actions = 0;
			if (name && strcmp(name, kInhibitedActions) == 0 && sd_bus_message_enter_container(m, 'v', "u") > 0) {
				if (sd_bus_message_read(m, "u", &actions) > 0) {
					i->apply(actions);
				}
				sd_bus_message_exit_container(m);
			} else {
				sd_bus_message_skip(m, "v");
			}
			sd_bus_message_exit_container(m);
		}
		sd_bus_message_exit_container(m);
		// Named as invalidated instead: changed, value not sent.
		char **invalidated = nullptr;
		if (sd_bus_message_read_strv(m, &invalidated) >= 0 && invalidated) {
			for (char **name = invalidated; *name; ++name) {
				uint32_t actions = 0;
				if (strcmp(*name, kInhibitedActions) == 0 && i->read(&actions)) {
					i->apply(actions);
				}
			}
			for (char **name = invalidated; *name; ++name) {
				free(*name);
			}
			free(invalidated);
		}
		return 0;
	}
};

GnomeIdleWatch::GnomeIdleWatch(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {
	impl_->owner = this;
}

std::unique_ptr<GnomeIdleWatch> GnomeIdleWatch::create(struct sd_bus *bus) {
	if (!bus) {
		return nullptr;
	}
	auto impl = std::make_unique<Impl>();
	impl->bus = bus;
	// Subscribed before the first read, so a change in between isn't missed.
	int r = sd_bus_match_signal(bus, &impl->changed_slot, kSmService, kSmPath, "org.freedesktop.DBus.Properties",
		"PropertiesChanged", Impl::on_properties_changed, impl.get());
	uint32_t actions = 0;
	if (r < 0 || !impl->read(&actions)) {
		WLOG_INFO("idle: gnome-session can't be asked, the client won't be kept awake for this session");
		sd_bus_slot_unref(impl->changed_slot);
		return nullptr;
	}
	auto watch = std::unique_ptr<GnomeIdleWatch>(new GnomeIdleWatch(std::move(impl)));
	watch->impl_->apply(actions);
	return watch;
}

GnomeIdleWatch::~GnomeIdleWatch() {
	sd_bus_slot_unref(impl_->changed_slot);
}

} // namespace wraith
