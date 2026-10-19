// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// What spectre's own UI (ui/session_menu.hpp, ui/stats_overlay.hpp) hands
// the renderer: a flat list of filled rectangles and text runs in window
// pixel coordinates (origin top-left), rebuilt from scratch whenever
// something changes. Deliberately dumb -- no retained widgets, no layout
// engine -- so OverlayRenderer::record_draw() is a loop over two vectors
// and the UI code has no Vulkan in it at all.
#pragma once

#include "ui/font.hpp"

#include <cmath>
#include <string>
#include <vector>

namespace spectre {

struct UiColor {
	float r = 1.0f, g = 1.0f, b = 1.0f, a = 1.0f;
};

struct UiRectPrim {
	float x = 0, y = 0, w = 0, h = 0; // window pixels
	UiColor color;                    // straight (non-premultiplied) alpha
};

struct UiTextPrim {
	float x = 0, y = 0; // top-left of the line box (baseline is y + UiFont::ascent() * scale), window pixels
	UiColor color;
	std::string text;
	// Drawn at this fraction of the font's size: the one atlas, scaled
	// (it is rasterized 2x oversampled, so moderately smaller stays crisp).
	// Every UiFont metric scales with it.
	float scale = 1.0f;
};

struct UiDrawList {
	std::vector<UiRectPrim> rects;
	std::vector<UiTextPrim> texts;

	void clear() {
		rects.clear();
		texts.clear();
	}

	void rect(float x, float y, float w, float h, UiColor color) { rects.push_back({x, y, w, h, color}); }
	void text(float x, float y, UiColor color, std::string str, float scale = 1.0f) {
		texts.push_back({x, y, color, std::move(str), scale});
	}

	// The shadow under a floating panel (the session menu, the fullscreen
	// toolbar, notices) whose outer edge, border included, is `x`,`y`,`w`,
	// `h`: cast down and a little to the right, as from a light above.
	// Copies of the footprint, each shifted further, so drawn before the
	// panel only its bottom and right edges show one, darkest next to it and
	// fading out; the renderer has no blur, and the steps stand in. `unit`
	// is the UI's scale unit, the font's pixel height / 4, so the shadow
	// grows with the display scale; `alpha` fades it with its panel.
	void drop_shadow(float x, float y, float w, float h, float unit, float alpha = 1.0f) {
		for (int i = 1; i <= 4; i++) {
			float dx = std::round((float)i * unit * 0.25f);
			float dy = std::round((float)i * unit * 0.6f);
			rect(x + dx, y + dy, w, h, {0.0f, 0.0f, 0.0f, 0.10f * alpha});
		}
	}

	// An X in the `size` px square at `x`,`y`, `stroke` px lines (the font
	// is ASCII only, and a letter x reads too small for a close button).
	// Two diagonals, each a stroke-sized square stepped one pixel at a
	// time: a solid 45-degree line of even width at any scale.
	void x_glyph(float x, float y, float size, float stroke, UiColor color) {
		for (float i = 0; i + stroke <= size; i += 1.0f) {
			rect(x + i, y + i, stroke, stroke, color);
			rect(x + size - stroke - i, y + i, stroke, stroke, color);
		}
	}
};

} // namespace spectre
