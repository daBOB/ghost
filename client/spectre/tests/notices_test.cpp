// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Plain-assert unit test for spectre's notices (ui/notices.hpp): toast
// stacking, tags, expiry and the hover pause; the prompt's rules (Allow
// inert at first, never on Enter, the timeout denying, queueing, cancel).
// With a directory argument, also renders each scenario over a mock
// desktop into PPM files there, through the same draw list the renderer
// gets, for checking the look by eye.
#include "ui/notices.hpp"

#undef NDEBUG
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <string>
#include <vector>

using namespace spectre;

namespace {

constexpr uint64_t kSec = 1000000;

void test_wrap() {
	UiFont font;
	assert(font.build(14));
	std::vector<std::string> one = wrap_text(font, "short", 1000, 1.0f);
	assert(one.size() == 1 && one[0] == "short");
	std::string long_text =
		"The host wants to erase every passkey on YubiKey 5C NFC and set it back to how it came";
	std::vector<std::string> lines = wrap_text(font, long_text, 200, 1.0f);
	assert(lines.size() > 1);
	for (const std::string &l : lines) {
		// Only a lone word may overflow.
		assert(font.text_width(l) <= 200 || l.find(' ') == std::string::npos);
	}
	std::vector<std::string> paras = wrap_text(font, "a\nb", 1000, 1.0f);
	assert(paras.size() == 2 && paras[0] == "a" && paras[1] == "b");
}

void test_toasts() {
	Notices n;
	uint64_t t = 10 * kSec;
	n.toast({NoticeLevel::kInfo, "one", "", 2 * kSec, ""}, t);
	n.toast({NoticeLevel::kInfo, "two", "", 2 * kSec, ""}, t);
	n.toast({NoticeLevel::kInfo, "three", "", 2 * kSec, ""}, t);
	n.toast({NoticeLevel::kInfo, "four", "", 2 * kSec, ""}, t);
	assert(n.toast_count() == Notices::kMaxToasts);
	assert(n.tick(t));

	// Same tag: replaced, not stacked.
	Notices m;
	m.toast({NoticeLevel::kInfo, "Session audio muted", "", 3 * kSec, "speaker"}, t);
	m.toast({NoticeLevel::kInfo, "Session audio on", "", 3 * kSec, "speaker"}, t);
	assert(m.toast_count() == 1);
	m.hide("speaker");
	assert(m.toast_count() == 0);

	// Expiry.
	Notices e;
	e.toast({NoticeLevel::kInfo, "bye", "", 2 * kSec, ""}, t);
	e.tick(t);
	assert(!e.tick(t + kSec) || e.toast_count() == 1);
	e.tick(t + 2 * kSec + 1);
	assert(e.toast_count() == 0);
}

void test_hover_and_click() {
	UiFont font;
	assert(font.build(14));
	UiDrawList dl;
	Notices n;
	uint64_t t = 10 * kSec;
	n.toast({NoticeLevel::kWarning, "The host refused YubiKey", "", 2 * kSec, ""}, t);
	n.build(dl, font, 1280, 800, 40, t);
	// Top-right: the panel ends near the right edge, below `top`.
	float max_x = 0, min_y = 1e9f;
	for (const UiRectPrim &r : dl.rects) {
		max_x = std::max(max_x, r.x + r.w);
		min_y = std::min(min_y, r.y);
	}
	assert(max_x <= 1280 && max_x > 1200);
	assert(min_y >= 40);

	// Hovered: the timer stops.
	assert(n.handle_pointer_motion(1250, 60));
	n.tick(t);
	n.tick(t + 5 * kSec);
	assert(n.toast_count() == 1);
	// Off it, it runs out.
	assert(!n.handle_pointer_motion(100, 400));
	n.tick(t + 5 * kSec + 1);
	n.tick(t + 8 * kSec);
	assert(n.toast_count() == 0);

	// A click on a toast takes it down and is spectre's; elsewhere isn't.
	n.toast({NoticeLevel::kInfo, "Sent report.pdf", "", 4 * kSec, ""}, t);
	dl.clear();
	n.build(dl, font, 1280, 800, 40, t);
	assert(!n.handle_pointer_press(100, 400, t));
	assert(n.handle_pointer_press(1250, 60, t));
	assert(n.toast_count() == 0);
}

void test_prompt() {
	UiFont font;
	assert(font.build(14));
	UiDrawList dl;
	uint64_t t = 10 * kSec;

	// Allow is inert for kArmUs, by key and by click; Enter and Space deny.
	{
		Notices n;
		uint64_t id = n.prompt({NoticeLevel::kWarning, "Reset", "erase it", "Erase", "Keep", 30 * kSec}, t);
		assert(n.prompt_visible());
		n.build(dl, font, 1280, 800, 40, t);
		n.handle_key(SDL_SCANCODE_A, t + 100000);
		assert(n.prompt_visible());
		// Anywhere is spectre's while a prompt is up.
		assert(n.handle_pointer_press(5, 700, t + 200000));
		assert(n.prompt_visible());
		n.handle_key(SDL_SCANCODE_A, t + Notices::kArmUs);
		assert(!n.prompt_visible());
		std::vector<PromptAnswer> a = n.take_answers();
		assert(a.size() == 1 && a[0].id == id && a[0].allowed && !a[0].timed_out);
		assert(n.take_answers().empty());
	}
	for (SDL_Scancode deny : {SDL_SCANCODE_RETURN, SDL_SCANCODE_SPACE, SDL_SCANCODE_ESCAPE, SDL_SCANCODE_D}) {
		Notices n;
		n.prompt({NoticeLevel::kWarning, "Reset", "", "Allow", "Deny", 30 * kSec}, t);
		n.handle_key(deny, t + 5 * kSec);
		std::vector<PromptAnswer> a = n.take_answers();
		assert(a.size() == 1 && !a[0].allowed && !a[0].timed_out);
	}
	// Clicking Allow, once armed.
	{
		Notices n;
		n.prompt({NoticeLevel::kWarning, "Reset", "", "Allow", "Deny", 30 * kSec}, t);
		dl.clear();
		n.build(dl, font, 1280, 800, 40, t);
		// Allow is the rightmost button: find it from the panel's right edge.
		float right = 0, bottom = 0;
		for (const UiRectPrim &r : dl.rects) {
			if (r.w < 1279) { // not the full-window dim
				right = std::max(right, r.x + r.w);
				bottom = std::max(bottom, r.y + r.h);
			}
		}
		float ax = right - 40, ay = bottom - 30;
		assert(n.handle_pointer_press(ax, ay, t + 500000));
		assert(n.prompt_visible());
		assert(n.handle_pointer_press(ax, ay, t + 2 * kSec));
		std::vector<PromptAnswer> a = n.take_answers();
		assert(a.size() == 1 && a[0].allowed);
	}
	// The timeout denies; queued prompts follow in order; cancel withdraws.
	{
		Notices n;
		uint64_t first = n.prompt({NoticeLevel::kWarning, "one", "", "Allow", "Deny", 10 * kSec}, t);
		uint64_t second = n.prompt({NoticeLevel::kWarning, "two", "", "Allow", "Deny", 10 * kSec}, t);
		uint64_t third = n.prompt({NoticeLevel::kWarning, "three", "", "Allow", "Deny", 10 * kSec}, t);
		n.tick(t);
		n.tick(t + 10 * kSec);
		std::vector<PromptAnswer> a = n.take_answers();
		assert(a.size() == 1 && a[0].id == first && !a[0].allowed && a[0].timed_out);
		// The second's clock starts when it shows, so Allow is inert again.
		n.handle_key(SDL_SCANCODE_A, t + 10 * kSec + 500000);
		assert(n.take_answers().empty());
		n.cancel(second);
		assert(n.take_answers().empty());
		assert(n.prompt_visible());
		n.cancel(third);
		assert(!n.prompt_visible());
	}
}

// --- preview rendering ---

struct Canvas {
	int w, h;
	std::vector<float> px; // RGB

	Canvas(int w_, int h_) : w(w_), h(h_), px((size_t)w_ * h_ * 3) {}

	void blend(int x, int y, UiColor c, float cover) {
		if (x < 0 || y < 0 || x >= w || y >= h) {
			return;
		}
		float a = c.a * cover;
		float *p = &px[((size_t)y * w + x) * 3];
		p[0] = p[0] * (1 - a) + c.r * a;
		p[1] = p[1] * (1 - a) + c.g * a;
		p[2] = p[2] * (1 - a) + c.b * a;
	}
	void rect(float x, float y, float rw, float rh, UiColor c) {
		for (int yy = (int)std::floor(y); yy < (int)std::ceil(y + rh); yy++) {
			for (int xx = (int)std::floor(x); xx < (int)std::ceil(x + rw); xx++) {
				blend(xx, yy, c, 1.0f);
			}
		}
	}
	// As OverlayRenderer::record_text: a quad per glyph, bilinear sample.
	void text(const UiFont &font, const UiTextPrim &t) {
		float pen = t.x;
		float baseline = t.y + (float)font.ascent() * t.scale;
		for (char c : t.text) {
			const UiFont::Glyph &g = font.glyph(c);
			float qx0 = pen + g.xoff * t.scale, qy0 = baseline + g.yoff * t.scale;
			int qw = (int)std::lround((g.xoff2 - g.xoff) * t.scale);
			int qh = (int)std::lround((g.yoff2 - g.yoff) * t.scale);
			for (int py = 0; py < qh; py++) {
				for (int px_ = 0; px_ < qw; px_++) {
					float u = g.x0 + (px_ + 0.5f) / qw * (g.x1 - g.x0) - 0.5f;
					float v = g.y0 + (py + 0.5f) / qh * (g.y1 - g.y0) - 0.5f;
					int ix = (int)std::floor(u), iy = (int)std::floor(v);
					float fx = u - ix, fy = v - iy;
					auto at = [&](int ax, int ay) {
						ax = std::clamp(ax, 0, font.atlas_width() - 1);
						ay = std::clamp(ay, 0, font.atlas_height() - 1);
						return (float)font.atlas()[(size_t)ay * font.atlas_width() + ax] / 255.0f;
					};
					float s = at(ix, iy) * (1 - fx) * (1 - fy) + at(ix + 1, iy) * fx * (1 - fy) +
						at(ix, iy + 1) * (1 - fx) * fy + at(ix + 1, iy + 1) * fx * fy;
					blend((int)std::lround(qx0) + px_, (int)std::lround(qy0) + py, t.color, s);
				}
			}
			pen += g.xadvance * t.scale;
		}
	}
	void draw(const UiFont &font, const UiDrawList &dl) {
		// The renderer draws every rect, then every text run.
		for (const UiRectPrim &r : dl.rects) {
			rect(r.x, r.y, r.w, r.h, r.color);
		}
		for (const UiTextPrim &t : dl.texts) {
			text(font, t);
		}
	}
	void save(const std::string &path) const {
		FILE *f = fopen(path.c_str(), "wb");
		assert(f);
		fprintf(f, "P6\n%d %d\n255\n", w, h);
		for (float v : px) {
			fputc((int)std::lround(std::clamp(v, 0.0f, 1.0f) * 255.0f), f);
		}
		fclose(f);
	}
};

// A dark remote desktop: a panel along the top with a status area at the
// right, and a maximized window whose title bar has its buttons there.
void mock_desktop(Canvas &c, const UiFont &font, float top) {
	c.rect(0, 0, (float)c.w, (float)c.h, {0.13f, 0.15f, 0.19f, 1});
	// spectre's docked toolbar band, when there is one.
	if (top > 0) {
		c.rect(0, 0, (float)c.w, top, {0.09f, 0.10f, 0.12f, 1});
	}
	c.rect(0, top, (float)c.w, 30, {0.06f, 0.06f, 0.08f, 1});
	UiTextPrim clock{(float)c.w / 2 - 30, top + 7, {0.85f, 0.85f, 0.85f, 1}, "Mon 15:42", 1.0f};
	c.text(font, clock);
	UiTextPrim status{(float)c.w - 120, top + 7, {0.85f, 0.85f, 0.85f, 1}, "wifi  vol  bat", 1.0f};
	c.text(font, status);
	c.rect(0, top + 30, (float)c.w, 34, {0.20f, 0.22f, 0.27f, 1});
	UiTextPrim title{12, top + 39, {0.9f, 0.9f, 0.9f, 1}, "Documents - Files", 1.0f};
	c.text(font, title);
	for (int i = 0; i < 3; i++) {
		c.rect((float)c.w - 34 - 30 * (float)i, top + 38, 18, 18,
			i == 0 ? UiColor{0.75f, 0.25f, 0.22f, 1} : UiColor{0.4f, 0.42f, 0.48f, 1});
	}
	c.rect(0, top + 64, (float)c.w, (float)c.h - top - 64, {0.16f, 0.17f, 0.21f, 1});
	for (int i = 0; i < 12; i++) {
		UiTextPrim row{40, top + 90 + 30 * (float)i, {0.80f, 0.80f, 0.82f, 1},
			"quarterly-report-" + std::to_string(2014 + i) + ".pdf          2.4 MB        Oct " +
				std::to_string(i + 3),
			1.0f};
		c.text(font, row);
	}
}

void render(const std::string &dir, const std::string &name, const Notices &n, uint64_t now, float top = 34) {
	UiFont font;
	assert(font.build(14));
	Canvas c(1280, 520);
	mock_desktop(c, font, top);
	UiDrawList dl;
	n.build(dl, font, c.w, c.h, top, now);
	c.draw(font, dl);
	c.save(dir + "/" + name + ".ppm");
}

void render_previews(const std::string &dir) {
	const uint64_t t = 100 * kSec, later = t + kSec; // past every fade-in
	{
		Notices n;
		n.toast({NoticeLevel::kInfo, "Session audio muted", "", 3 * kSec, "speaker"}, t);
		render(dir, "1-toast-info", n, later);
	}
	{
		Notices n;
		n.toast({NoticeLevel::kInfo, "Security key forwarded: YubiKey 5C NFC", "", 4 * kSec, ""}, t);
		n.toast({NoticeLevel::kSuccess, "Sent quarterly-report-2025.pdf", "to Downloads", 4 * kSec, ""}, t);
		n.toast({NoticeLevel::kWarning, "The host tried to reset YubiKey 5C NFC",
					"Refused. Manage security keys on this computer.", 10 * kSec, ""},
			t);
		render(dir, "2-toast-stack", n, later);
	}
	{
		Notices n;
		n.toast({NoticeLevel::kError, "report.pdf: permission denied", "", 4 * kSec, ""}, t);
		n.toast({NoticeLevel::kWarning, "The host refused YubiKey 5C NFC", "", 4 * kSec, ""}, t);
		UiFont font;
		assert(font.build(14));
		UiDrawList dl;
		n.build(dl, font, 1280, 520, 34, later); // lay out, for hit testing
		n.handle_pointer_motion(1200, 60);       // over the newest
		render(dir, "3-toast-hovered", n, later);
	}
	{
		Notices n;
		n.toast({NoticeLevel::kInfo, "Session audio muted", "", 3 * kSec, ""}, t);
		n.prompt({NoticeLevel::kWarning, "Erase this security key?",
					 "The host wants to reset YubiKey 5C NFC. This erases every passkey on it and its PIN, "
					 "and can't be undone.",
					 "Erase", "Keep", 30 * kSec},
			t);
		render(dir, "4-prompt-not-armed", n, t + 300000);
		render(dir, "5-prompt-armed", n, t + 3 * kSec);
	}
	{
		Notices n;
		n.prompt({NoticeLevel::kWarning, "Generate a new key in PIV slot 9a?",
					 "The host wants to replace the authentication key on YubiKey 5C NFC. Anything that "
					 "signs in with the old key stops working.",
					 "Replace", "Keep", 30 * kSec},
			t);
		n.prompt({NoticeLevel::kWarning, "second", "", "Allow", "Deny", 30 * kSec}, t);
		render(dir, "6-prompt-fullscreen-queued", n, t + 12 * kSec, 0);
	}
}

} // namespace

int main(int argc, char **argv) {
	test_wrap();
	test_toasts();
	test_hover_and_click();
	test_prompt();
	if (argc > 1) {
		render_previews(argv[1]);
	}
	printf("notices_test: ok\n");
	return 0;
}
