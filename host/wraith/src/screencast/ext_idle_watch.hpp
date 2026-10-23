// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// ExtIdleWatch: IdleWatch over ext-idle-notify-v1 version 2, for the
// backends that reach their compositor as a Wayland client (screencast-ext,
// screencast-kwin). The protocol has no "is anything inhibiting?" query, so
// this asks it with two notifications:
//
// - one from get_input_idle_notification (input alone, inhibitors
//   ignored), at kInputMs: whether anyone is at the seat;
// - a probe from get_idle_notification, at the shorter kProbeMs, which an
//   inhibitor keeps from going idle.
//
// The seat idle for input while the probe stays awake is an inhibitor at
// work. The probe's shorter timeout keeps the two apart: with one timeout
// for both, their idled events come together in either order (kwin sent
// the input one first), which read as a hold for a moment every time the
// user stopped.
//
// An inhibitor taken while the probe is already idle wakes nothing: kwin
// only stops the probe's timer then, it sends no resumed. So while the seat
// is idle and the probe with it, the probe is made again every kRecheckMs;
// a fresh one idles within kProbeMs unless something inhibits. A video
// that starts on its own (a playlist's next) is seen within about two
// rechecks, one dropped as soon as the probe idles.
//
// While there is input neither can tell, and the last answer stands: the
// user is at the client then, whose display stays awake regardless.
#pragma once

#include "screencast/idle_watch.hpp"

#include <memory>

struct wl_event_loop;

namespace wraith {

class WaylandClient;

class ExtIdleWatch : public IdleWatch {
public:
	// Null if the compositor exports no ext_idle_notifier_v1, or only
	// version 1 (no input-only notification to compare against). `client`
	// must outlive the returned object.
	static std::unique_ptr<ExtIdleWatch> create(WaylandClient &client, struct wl_event_loop *loop);

	~ExtIdleWatch() override;

	static constexpr unsigned kInputMs = 5000;
	static constexpr unsigned kProbeMs = 2500;
	static constexpr unsigned kRecheckMs = 3000;

private:
	struct Impl;
	explicit ExtIdleWatch(std::unique_ptr<Impl> impl);
	std::unique_ptr<Impl> impl_;
};

} // namespace wraith
