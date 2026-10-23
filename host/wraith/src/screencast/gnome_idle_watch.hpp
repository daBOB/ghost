// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// GnomeIdleWatch: IdleWatch for `Backend=screencast-gnome`. mutter exports
// no ext-idle-notify-v1; every idle inhibitor in a GNOME session ends up
// with gnome-session instead -- mutter takes one there for a Wayland
// client's zwp_idle_inhibitor_v1, the portal's Inhibit asks it directly --
// and it publishes the union as its InhibitedActions property:
//
//   org.gnome.SessionManager /org/gnome/SessionManager
//     InhibitedActions (u): GsmInhibitorFlag bits, 8 = idle
//
// Read once, then followed through PropertiesChanged. Unlike ExtIdleWatch
// there is no delay: the property changes as the inhibitor comes and goes.
#pragma once

#include "screencast/idle_watch.hpp"

#include <memory>

struct sd_bus;

namespace wraith {

class GnomeIdleWatch : public IdleWatch {
public:
	// `bus` is GnomeRemoteSession's (the session bus, already on the event
	// loop) and must outlive this object. Null if gnome-session can't be
	// asked -- a session started without it.
	static std::unique_ptr<GnomeIdleWatch> create(struct sd_bus *bus);

	~GnomeIdleWatch() override;

private:
	struct Impl;
	explicit GnomeIdleWatch(std::unique_ptr<Impl> impl);
	std::unique_ptr<Impl> impl_;
};

} // namespace wraith
