// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "screencast/idle_watch.hpp"

#include "util/log.hpp"

namespace wraith {

void IdleWatch::set_inhibited(bool inhibited) {
	if (inhibited == inhibited_) {
		return;
	}
	inhibited_ = inhibited;
	WLOG_INFO("idle: the desktop %s", inhibited ? "is held awake" : "is no longer held awake");
	if (on_changed) {
		on_changed(inhibited);
	}
}

} // namespace wraith
