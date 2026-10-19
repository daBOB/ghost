// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "ui/notices.hpp"

#include <algorithm>
#include <cmath>

namespace spectre {

namespace {

// The panel is a shade lighter than the session menu's and nearly opaque,
// so it holds up over a dark desktop; the level's accent (the stripe, the
// title, a prompt's border) is what catches the eye.
const UiColor kPanel{0.11f, 0.12f, 0.15f, 0.97f};
const UiColor kBorder{0.30f, 0.34f, 0.42f, 1.0f};
const UiColor kText{0.93f, 0.93f, 0.95f, 1.0f};
const UiColor kDim{0.58f, 0.60f, 0.65f, 1.0f};
const UiColor kDimVideo{0.0f, 0.0f, 0.0f, 0.45f};
// The session menu's button colours (ui/session_menu.cpp).
const UiColor kCell{0.17f, 0.18f, 0.23f, 1.0f};
const UiColor kHighlight{0.20f, 0.36f, 0.60f, 1.0f};

constexpr float kTitleScale = 1.2f;
constexpr float kBodyScale = 1.1f;
// A toast under the pointer: see-through, so what it covers shows.
constexpr float kHoverAlpha = 0.18f;
constexpr uint64_t kFadeInUs = 150000;

UiColor accent(NoticeLevel level) {
	switch (level) {
	case NoticeLevel::kInfo: return {0.60f, 0.78f, 1.00f, 1.0f};
	case NoticeLevel::kSuccess: return {0.48f, 0.86f, 0.58f, 1.0f};
	case NoticeLevel::kWarning: return {1.00f, 0.76f, 0.30f, 1.0f};
	case NoticeLevel::kError: return {1.00f, 0.48f, 0.45f, 1.0f};
	}
	return kText;
}

UiColor faded(UiColor c, float alpha) {
	c.a *= alpha;
	return c;
}

// An accent darkened to sit behind kText: an armed Allow under the pointer.
UiColor button_fill(UiColor c) {
	return {c.r * 0.45f, c.g * 0.45f, c.b * 0.45f, 1.0f};
}

struct Metrics {
	float s, margin, pad_x, pad_y, gap, stripe, border, max_w, min_w;
	float title_lh, body_lh;
};

Metrics metrics(const UiFont &font, int win_w) {
	Metrics m{};
	m.s = (float)font.pixel_height() / 4.0f; // see session_menu.cpp
	m.margin = std::round(4 * m.s);
	m.pad_x = std::round(4 * m.s);
	m.pad_y = std::round(3 * m.s);
	m.gap = std::round(2 * m.s);
	m.stripe = std::max(3.0f, std::round(m.s));
	m.border = std::max(1.0f, std::floor(m.s / 2));
	m.max_w = std::min((float)win_w - 2 * m.margin, (float)font.pixel_height() * 34);
	m.min_w = std::min(m.max_w, (float)font.pixel_height() * 16);
	m.title_lh = std::ceil((float)font.line_height() * kTitleScale);
	m.body_lh = std::ceil((float)font.line_height() * kBodyScale);
	return m;
}

float widest(const UiFont &font, const std::vector<std::string> &lines, float scale) {
	float w = 0;
	for (const std::string &l : lines) {
		w = std::max(w, font.text_width(l) * scale);
	}
	return w;
}

std::string countdown_text(uint64_t remaining_us) {
	uint64_t s = (remaining_us + 999999) / 1000000;
	return "Denies in " + std::to_string(s) + " s";
}

} // namespace

std::vector<std::string> wrap_text(const UiFont &font, const std::string &text, float max_w, float scale) {
	std::vector<std::string> lines;
	size_t start = 0;
	while (start <= text.size()) {
		size_t nl = text.find('\n', start);
		std::string para = text.substr(start, nl == std::string::npos ? std::string::npos : nl - start);
		std::string line;
		size_t i = 0;
		while (i < para.size()) {
			size_t sp = para.find(' ', i);
			std::string word = para.substr(i, sp == std::string::npos ? std::string::npos : sp - i);
			i = sp == std::string::npos ? para.size() : sp + 1;
			if (word.empty()) {
				continue;
			}
			std::string candidate = line.empty() ? word : line + " " + word;
			if (!line.empty() && font.text_width(candidate) * scale > max_w) {
				lines.push_back(line);
				line = word;
			} else {
				line = candidate;
			}
		}
		if (!line.empty() || !para.empty() || lines.empty()) {
			lines.push_back(line);
		}
		if (nl == std::string::npos) {
			break;
		}
		start = nl + 1;
	}
	return lines;
}

void Notices::toast(ToastSpec spec, uint64_t now_us) {
	if (!spec.tag.empty()) {
		for (Toast &t : toasts_) {
			if (t.spec.tag == spec.tag) {
				t.remaining_us = spec.duration_us;
				t.last_us = now_us;
				t.spec = std::move(spec);
				dirty_ = true;
				return;
			}
		}
	}
	Toast t;
	t.id = next_id_++;
	t.remaining_us = spec.duration_us;
	t.spec = std::move(spec);
	t.shown_us = now_us;
	t.last_us = now_us;
	toasts_.push_front(std::move(t));
	while (toasts_.size() > kMaxToasts) {
		toasts_.pop_back();
	}
	dirty_ = true;
}

void Notices::hide(const std::string &tag) {
	auto it = std::find_if(toasts_.begin(), toasts_.end(), [&](const Toast &t) { return t.spec.tag == tag; });
	if (it != toasts_.end()) {
		if (hovered_toast_ == it->id) {
			hovered_toast_ = 0;
		}
		toasts_.erase(it);
		dirty_ = true;
	}
}

void Notices::clear_toasts() {
	if (!toasts_.empty()) {
		toasts_.clear();
		hovered_toast_ = 0;
		dirty_ = true;
	}
}

uint64_t Notices::prompt(PromptSpec spec, uint64_t now_us) {
	Prompt p;
	p.id = next_id_++;
	p.spec = std::move(spec);
	prompts_.push_back(std::move(p));
	if (prompts_.size() == 1) {
		show_next_prompt(now_us);
	}
	dirty_ = true;
	return prompts_.back().id;
}

void Notices::cancel(uint64_t id) {
	for (size_t i = 0; i < prompts_.size(); i++) {
		if (prompts_[i].id != id) {
			continue;
		}
		uint64_t now_us = prompts_[i].shown_us ? now_us_ : 0;
		prompts_.erase(prompts_.begin() + (ptrdiff_t)i);
		if (i == 0) {
			show_next_prompt(now_us);
		}
		dirty_ = true;
		return;
	}
}

std::vector<PromptAnswer> Notices::take_answers() {
	std::vector<PromptAnswer> out;
	out.swap(answers_);
	return out;
}

void Notices::show_next_prompt(uint64_t now_us) {
	hovered_button_ = Button::kNone;
	last_countdown_s_ = -1;
	last_armed_ = false;
	if (!prompts_.empty()) {
		prompts_.front().shown_us = std::max<uint64_t>(now_us, 1);
	}
}

void Notices::answer(bool allowed, bool timed_out) {
	if (prompts_.empty()) {
		return;
	}
	answers_.push_back({prompts_.front().id, allowed, timed_out});
	prompts_.pop_front();
	show_next_prompt(now_us_);
	dirty_ = true;
}

bool Notices::armed(uint64_t now_us) const {
	return !prompts_.empty() && now_us >= prompts_.front().shown_us + kArmUs;
}

bool Notices::tick(uint64_t now_us) {
	now_us_ = now_us;
	bool changed = dirty_;
	dirty_ = false;
	for (auto it = toasts_.begin(); it != toasts_.end();) {
		uint64_t elapsed = now_us > it->last_us ? now_us - it->last_us : 0;
		it->last_us = now_us;
		if (it->id != hovered_toast_) {
			it->remaining_us = it->remaining_us > elapsed ? it->remaining_us - elapsed : 0;
		}
		if (it->remaining_us == 0) {
			it = toasts_.erase(it);
			changed = true;
		} else {
			++it;
		}
	}
	bool fading = std::any_of(toasts_.begin(), toasts_.end(),
		[&](const Toast &t) { return now_us - t.shown_us < kFadeInUs; });
	// One more redraw after the last fade step, to land on full opacity.
	changed = changed || fading || fading_;
	fading_ = fading;
	if (!prompts_.empty()) {
		const Prompt &p = prompts_.front();
		uint64_t elapsed = now_us - p.shown_us;
		if (elapsed >= p.spec.timeout_us) {
			answer(false, true);
			dirty_ = false;
			return true;
		}
		int64_t s = (int64_t)((p.spec.timeout_us - elapsed + 999999) / 1000000);
		bool is_armed = armed(now_us);
		changed = changed || s != last_countdown_s_ || is_armed != last_armed_;
		last_countdown_s_ = s;
		last_armed_ = is_armed;
	}
	return changed;
}

void Notices::handle_key(SDL_Scancode scancode, uint64_t now_us) {
	now_us_ = now_us;
	if (prompts_.empty()) {
		return;
	}
	switch (scancode) {
	case SDL_SCANCODE_ESCAPE:
	case SDL_SCANCODE_D:
	case SDL_SCANCODE_RETURN:
	case SDL_SCANCODE_KP_ENTER:
	case SDL_SCANCODE_SPACE: answer(false, false); break;
	case SDL_SCANCODE_A:
		if (armed(now_us)) {
			answer(true, false);
		}
		break;
	default: break;
	}
}

Notices::Button Notices::button_at(float x, float y) const {
	if (allow_rect_.contains(x, y)) {
		return Button::kAllow;
	}
	if (deny_rect_.contains(x, y)) {
		return Button::kDeny;
	}
	return Button::kNone;
}

bool Notices::handle_pointer_motion(float x, float y) {
	if (!prompts_.empty()) {
		Button b = button_at(x, y);
		if (b != hovered_button_) {
			hovered_button_ = b;
			dirty_ = true;
		}
		return true;
	}
	uint64_t hovered = 0;
	for (const auto &[id, r] : toast_rects_) {
		if (r.contains(x, y)) {
			hovered = id;
			break;
		}
	}
	if (hovered != hovered_toast_) {
		hovered_toast_ = hovered;
		dirty_ = true;
	}
	return hovered != 0;
}

void Notices::handle_pointer_left() {
	if (hovered_toast_ != 0 || hovered_button_ != Button::kNone) {
		hovered_toast_ = 0;
		hovered_button_ = Button::kNone;
		dirty_ = true;
	}
}

bool Notices::handle_pointer_press(float x, float y, uint64_t now_us) {
	now_us_ = now_us;
	if (!prompts_.empty()) {
		switch (button_at(x, y)) {
		case Button::kAllow:
			if (armed(now_us)) {
				answer(true, false);
			}
			break;
		case Button::kDeny: answer(false, false); break;
		case Button::kNone: break;
		}
		return true;
	}
	for (const auto &[id, r] : toast_rects_) {
		if (!r.contains(x, y)) {
			continue;
		}
		uint64_t gone = id;
		toasts_.erase(
			std::remove_if(toasts_.begin(), toasts_.end(), [&](const Toast &t) { return t.id == gone; }),
			toasts_.end());
		if (hovered_toast_ == gone) {
			hovered_toast_ = 0;
		}
		dirty_ = true;
		return true;
	}
	return false;
}

void Notices::build(UiDrawList &out, const UiFont &font, int win_w, int win_h, float top,
	uint64_t now_us) const {
	toast_rects_.clear();
	allow_rect_ = deny_rect_ = Rect{};
	if ((toasts_.empty() && prompts_.empty()) || !font.valid()) {
		return;
	}
	const Metrics m = metrics(font, win_w);
	const float text_w = m.max_w - m.stripe - 2 * m.pad_x;

	// Laid out first, drawn second: the toasts share one width, the
	// widest one's, so the stack's right edge and left edge both line up.
	struct ToastLayout {
		const Toast *t;
		std::vector<std::string> title, body;
		float h;
	};
	std::vector<ToastLayout> laid;
	float toast_w = m.min_w;
	for (const Toast &t : toasts_) {
		ToastLayout l{&t, wrap_text(font, t.spec.title, text_w, kTitleScale), {}, 0};
		float w = widest(font, l.title, kTitleScale);
		if (!t.spec.body.empty()) {
			l.body = wrap_text(font, t.spec.body, text_w, kBodyScale);
			w = std::max(w, widest(font, l.body, kBodyScale));
		}
		toast_w = std::max(toast_w, std::ceil(w + m.stripe + 2 * m.pad_x));
		l.h = 2 * m.pad_y + (float)l.title.size() * m.title_lh +
			(l.body.empty() ? 0.0f : m.gap / 2 + (float)l.body.size() * m.body_lh);
		laid.push_back(std::move(l));
	}
	toast_w = std::min(toast_w, m.max_w);

	float y = std::floor(top + m.margin);

	if (!prompts_.empty()) {
		const Prompt &p = prompts_.front();
		const UiColor acc = accent(p.spec.level);
		// Dim everything, toolbar included: the prompt has the input.
		out.rect(0, 0, (float)win_w, (float)win_h, kDimVideo);

		std::vector<std::string> title = wrap_text(font, p.spec.title, text_w, kTitleScale);
		std::vector<std::string> body = wrap_text(font, p.spec.body, text_w, kBodyScale);
		const bool is_armed = armed(now_us);
		const std::string deny = p.spec.deny_label + " (Esc)";
		const std::string allow = p.spec.allow_label + " (A)";
		const float btn_pad_x = std::round(3 * m.s), btn_pad_y = std::round(1.5f * m.s);
		const float btn_h = m.body_lh + 2 * btn_pad_y;
		const float deny_w = std::ceil(font.text_width(deny) * kBodyScale + 2 * btn_pad_x);
		const float allow_w = std::ceil(font.text_width(allow) * kBodyScale + 2 * btn_pad_x);

		const float w = m.max_w;
		const float h = 2 * m.pad_y + (float)title.size() * m.title_lh + m.gap / 2 +
			(float)body.size() * m.body_lh + 2 * m.gap + btn_h;
		const float x = std::floor((float)win_w - m.margin - w);
		const float bw = 2 * m.border;

		out.drop_shadow(x - bw, y - bw, w + 2 * bw, h + 2 * bw, m.s);
		out.rect(x - bw, y - bw, w + 2 * bw, h + 2 * bw, acc);
		out.rect(x, y, w, h, kPanel);
		out.rect(x, y, m.stripe, h, acc);

		float tx = x + m.stripe + m.pad_x;
		float ty = y + m.pad_y;
		for (const std::string &l : title) {
			out.text(tx, ty, acc, l, kTitleScale);
			ty += m.title_lh;
		}
		ty += m.gap / 2;
		for (const std::string &l : body) {
			out.text(tx, ty, kText, l, kBodyScale);
			ty += m.body_lh;
		}
		ty += 2 * m.gap;

		// Deny then Allow at the right; the countdown at the left.
		const float right = x + w - m.pad_x;
		allow_rect_ = {right - allow_w, ty, allow_w, btn_h};
		deny_rect_ = {allow_rect_.x - m.gap - deny_w, ty, deny_w, btn_h};

		out.rect(deny_rect_.x, deny_rect_.y, deny_rect_.w, deny_rect_.h, kHighlight);
		if (hovered_button_ == Button::kDeny) {
			const float b = m.border;
			out.rect(deny_rect_.x - b, deny_rect_.y - b, deny_rect_.w + 2 * b, deny_rect_.h + 2 * b, kText);
			out.rect(deny_rect_.x, deny_rect_.y, deny_rect_.w, deny_rect_.h, kHighlight);
		}
		out.text(deny_rect_.x + btn_pad_x, deny_rect_.y + btn_pad_y, kText, deny, kBodyScale);

		UiColor allow_fill = is_armed && hovered_button_ == Button::kAllow ? button_fill(acc) : kCell;
		out.rect(allow_rect_.x, allow_rect_.y, allow_rect_.w, allow_rect_.h, allow_fill);
		out.text(allow_rect_.x + btn_pad_x, allow_rect_.y + btn_pad_y, is_armed ? kText : kDim, allow,
			kBodyScale);

		uint64_t elapsed = now_us - p.shown_us;
		uint64_t left = p.spec.timeout_us > elapsed ? p.spec.timeout_us - elapsed : 0;
		std::string status = countdown_text(left);
		if (prompts_.size() > 1) {
			status += " (+" + std::to_string(prompts_.size() - 1) + " more)";
		}
		out.text(tx, ty + btn_pad_y + (m.body_lh - m.body_lh / kBodyScale) / 2, kDim, status);

		y += h + 2 * bw + m.gap * 2;
	}

	const float x = std::floor((float)win_w - m.margin - toast_w);
	for (const ToastLayout &l : laid) {
		const Toast &t = *l.t;
		const UiColor acc = accent(t.spec.level);
		float alpha = std::min(1.0f, (float)(now_us - t.shown_us) / (float)kFadeInUs);
		if (t.id == hovered_toast_ && prompts_.empty()) {
			alpha = kHoverAlpha;
		}
		if (!prompts_.empty()) {
			alpha *= 0.5f; // under the dim, like the rest: the prompt is what to answer
		}
		const float h = l.h;
		const float b = m.border;
		out.drop_shadow(x - b, y - b, toast_w + 2 * b, h + 2 * b, m.s, alpha);
		out.rect(x - b, y - b, toast_w + 2 * b, h + 2 * b, faded(kBorder, alpha));
		out.rect(x, y, toast_w, h, faded(kPanel, alpha));
		out.rect(x, y, m.stripe, h, faded(acc, alpha));
		toast_rects_.push_back({t.id, Rect{x - b, y - b, toast_w + 2 * b, h + 2 * b}});

		// The title takes the accent when there is a body under it, or when
		// the toast is a warning or an error; otherwise the stripe alone
		// says what kind it is.
		bool accent_title =
			!l.body.empty() || t.spec.level == NoticeLevel::kWarning || t.spec.level == NoticeLevel::kError;
		float tx = x + m.stripe + m.pad_x;
		float ty = y + m.pad_y;
		for (const std::string &line : l.title) {
			out.text(tx, ty, faded(accent_title ? acc : kText, alpha), line, kTitleScale);
			ty += m.title_lh;
		}
		if (!l.body.empty()) {
			ty += m.gap / 2;
			for (const std::string &line : l.body) {
				out.text(tx, ty, faded(kText, alpha), line, kBodyScale);
				ty += m.body_lh;
			}
		}
		y += h + 2 * b + m.gap;
		if (y > (float)win_h) {
			break;
		}
	}
}

} // namespace spectre
