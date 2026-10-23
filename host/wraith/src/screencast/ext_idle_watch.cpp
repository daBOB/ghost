// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "screencast/ext_idle_watch.hpp"

#include "screencast/wayland_client.hpp"
#include "util/event_source.hpp"

#include <ext-idle-notify-v1-client-protocol.h>
#include <wayland-client-protocol.h>
#include <wayland-server-core.h>

#include "util/log.hpp"

namespace wraith {

struct ExtIdleWatch::Impl {
	ExtIdleWatch *owner = nullptr;
	WaylandClient *client = nullptr;
	struct wl_seat *seat = nullptr;
	struct ext_idle_notifier_v1 *notifier = nullptr;
	struct ext_idle_notification_v1 *input = nullptr;
	struct ext_idle_notification_v1 *probe = nullptr;
	EventSource recheck;
	bool input_idle = false;
	bool probe_idle = false;
	// A probe made by a recheck that hasn't idled yet: no answer until it
	// does, or the next recheck finds it still awake.
	bool probing = false;

	void update() {
		if (input_idle && !probing) {
			owner->set_inhibited(!probe_idle);
		}
	}

	void make_probe() {
		static const struct ext_idle_notification_v1_listener listener = {
			.idled = on_probe_idled,
			.resumed = on_probe_resumed,
		};
		if (probe) {
			ext_idle_notification_v1_destroy(probe);
		}
		probe = ext_idle_notifier_v1_get_idle_notification(notifier, kProbeMs, seat);
		ext_idle_notification_v1_add_listener(probe, &listener, this);
		probe_idle = false;
		client->flush();
	}

	void on_recheck() {
		if (!input_idle) {
			return;
		}
		if (probing) {
			probing = false; // still awake a whole recheck later: held
			update();
		} else if (probe_idle) {
			make_probe();
			probing = true;
		}
		wl_event_source_timer_update(recheck.get(), kRecheckMs);
	}

	static void on_input_idled(void *data, struct ext_idle_notification_v1 *) {
		auto *i = static_cast<Impl *>(data);
		i->input_idle = true;
		i->update();
		wl_event_source_timer_update(i->recheck.get(), kRecheckMs);
	}
	static void on_input_resumed(void *data, struct ext_idle_notification_v1 *) {
		auto *i = static_cast<Impl *>(data);
		i->input_idle = false;
		i->probing = false;
		wl_event_source_timer_update(i->recheck.get(), 0);
	}
	static void on_probe_idled(void *data, struct ext_idle_notification_v1 *) {
		auto *i = static_cast<Impl *>(data);
		i->probe_idle = true;
		i->probing = false;
		i->update();
	}
	static void on_probe_resumed(void *data, struct ext_idle_notification_v1 *) {
		auto *i = static_cast<Impl *>(data);
		i->probe_idle = false;
		i->update();
	}
};

ExtIdleWatch::ExtIdleWatch(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {
	impl_->owner = this;
}

std::unique_ptr<ExtIdleWatch> ExtIdleWatch::create(WaylandClient &client, struct wl_event_loop *loop) {
	if (!client.has_global(ext_idle_notifier_v1_interface.name)) {
		WLOG_INFO("idle: the compositor exports no ext_idle_notifier_v1, "
				  "the client won't be kept awake for this session");
		return nullptr;
	}
	auto impl = std::make_unique<Impl>();
	impl->client = &client;
	impl->notifier = static_cast<struct ext_idle_notifier_v1 *>(client.bind(&ext_idle_notifier_v1_interface, 2));
	if (impl->notifier && wl_proxy_get_version(reinterpret_cast<struct wl_proxy *>(impl->notifier)) < 2) {
		WLOG_INFO("idle: the compositor's ext_idle_notifier_v1 has no input-only notification (version 1), "
				  "the client won't be kept awake for this session");
		ext_idle_notifier_v1_destroy(impl->notifier);
		return nullptr;
	}
	// A seat proxy of this watch's own, like the clipboard's.
	impl->seat = static_cast<struct wl_seat *>(client.bind(&wl_seat_interface, 1));
	if (!impl->notifier || !impl->seat) {
		WLOG_ERROR("idle: binding ext_idle_notifier_v1/wl_seat failed");
		if (impl->notifier) {
			ext_idle_notifier_v1_destroy(impl->notifier);
		}
		if (impl->seat) {
			wl_seat_destroy(impl->seat);
		}
		return nullptr;
	}

	impl->recheck.reset(wl_event_loop_add_timer(
		loop,
		[](void *data) {
			static_cast<Impl *>(data)->on_recheck();
			return 0;
		},
		impl.get()));
	static const struct ext_idle_notification_v1_listener input_listener = {
		.idled = Impl::on_input_idled,
		.resumed = Impl::on_input_resumed,
	};
	impl->input = ext_idle_notifier_v1_get_input_idle_notification(impl->notifier, kInputMs, impl->seat);
	ext_idle_notification_v1_add_listener(impl->input, &input_listener, impl.get());
	impl->make_probe();
	return std::unique_ptr<ExtIdleWatch>(new ExtIdleWatch(std::move(impl)));
}

ExtIdleWatch::~ExtIdleWatch() {
	Impl &i = *impl_;
	i.recheck.reset();
	ext_idle_notification_v1_destroy(i.input);
	ext_idle_notification_v1_destroy(i.probe);
	ext_idle_notifier_v1_destroy(i.notifier);
	wl_seat_destroy(i.seat);
	i.client->flush();
}

} // namespace wraith
