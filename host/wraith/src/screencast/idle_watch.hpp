// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// IdleWatch: whether an application in the captured desktop is holding it
// awake -- a video playing, a game -- so the client can keep its own display
// awake meanwhile (gdp-spec.md §7.13). A RemoteSession makes one per open()
// (RemoteSession::make_idle_watch()): ExtIdleWatch asks the compositor over
// ext-idle-notify-v1 (labwc, kwin), GnomeIdleWatch asks gnome-session.
#pragma once

#include <functional>

namespace wraith {

class IdleWatch {
public:
	virtual ~IdleWatch() = default;
	// Already current when the watch is returned; on_changed follows it.
	bool inhibited() const { return inhibited_; }
	// Fires on each change, from the event loop.
	std::function<void(bool inhibited)> on_changed;

protected:
	// Logs and fires on_changed when `inhibited` differs from the last.
	void set_inhibited(bool inhibited);

private:
	bool inhibited_ = false;
};

} // namespace wraith
