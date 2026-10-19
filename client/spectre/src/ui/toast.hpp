// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// A message centred over the video until taken down: the "logging out"
// notice that stays up until the session ends, since it is the state of
// the whole session. Everything shorter-lived is a toast in the corner
// (ui/notices.hpp).
//
// Pure state + layout, like ui/tile_debug_overlay.hpp: the caller shows
// it, retires it from its main loop with expire(), and draws what build()
// appends.
#pragma once

#include "ui/draw_list.hpp"
#include "ui/font.hpp"

#include <cstdint>
#include <string>

namespace spectre {

class Toast {
public:
	// Shows `text` until now_us + `duration_us`, replacing whatever was up.
	// `now_us` is gdp::monotonic_us().
	void show(std::string text, uint64_t now_us, uint64_t duration_us);
	// Shows `text` until hide().
	void show(std::string text);

	void hide() { text_.clear(); }

	// Drops the message once its time is up. Returns true if it went away,
	// i.e. the caller needs a redraw -- an idle desktop sends no frame that
	// would repaint it away otherwise.
	bool expire(uint64_t now_us);

	// Appends the message (nothing when none is up), centred horizontally
	// in the `win_w` x `win_h` window and a quarter of the way down the
	// video, which starts `top` window pixels down (below the docked
	// toolbar).
	void build(UiDrawList &out, const UiFont &font, int win_w, int win_h, float top) const;

private:
	std::string text_;
	uint64_t expires_us_ = 0;
};

} // namespace spectre
