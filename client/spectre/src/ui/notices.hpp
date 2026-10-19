// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// spectre's notices: short toasts and the consent prompt, stacked in the
// top-right corner of the video (below the docked toolbar when windowed),
// drawn by spectre and never part of the remote picture.
//
// Toasts are passive and timed. Up to kMaxToasts show at once, newest on
// top; a toast with the same tag as one already up replaces it in place
// (pressing mute twice doesn't stack two notices). While the pointer is
// over a toast it turns nearly transparent, so whatever it covers on the
// remote desktop (a maximized window's close button, the panel's status
// menu) can be seen, and its timer stops. A click on it dismisses it and
// isn't forwarded.
//
// A prompt asks the user to allow or deny something the host asked for.
// It sits above the toasts with an accented border, dims the rest of the
// video, and owns the keyboard and pointer while up, like the session
// menu. Its rules are there because the host controls the picture and
// the timing of the user's input:
//   - Deny is the default. Esc, D, Enter and Space deny.
//   - Allow takes a click on its button or the A key, and neither works
//     for kArmUs after the prompt appears, so a click or keypress the
//     host times to land on it goes nowhere.
//   - Unanswered, it denies itself after its timeout, counting down on
//     screen.
//   - It never asks for a secret.
// Prompts queue: one shows at a time, in the order asked.
//
// Pure state + layout, like ui/session_menu.hpp: the caller feeds it time,
// keys and pointer positions in window pixels, drains take_answers(), and
// draws what build() appends.
#pragma once

#include "ui/draw_list.hpp"
#include "ui/font.hpp"

#include <SDL3/SDL_scancode.h>

#include <cstdint>
#include <deque>
#include <string>
#include <vector>

namespace spectre {

enum class NoticeLevel {
	kInfo,    // a setting changed, a device came or went
	kSuccess, // something the user asked for finished
	kWarning, // something needs the user's attention, or was refused
	kError,   // something failed
};

struct ToastSpec {
	NoticeLevel level = NoticeLevel::kInfo;
	std::string title;
	std::string body; // optional second paragraph, in the plain text colour
	uint64_t duration_us = 4000000;
	// Non-empty: replaces an up toast with the same tag rather than
	// stacking, and hide(tag) takes it down.
	std::string tag;
};

struct PromptSpec {
	NoticeLevel level = NoticeLevel::kWarning;
	std::string title;
	std::string body;
	std::string allow_label = "Allow";
	std::string deny_label = "Deny";
	uint64_t timeout_us = 30000000;
};

struct PromptAnswer {
	uint64_t id = 0;
	bool allowed = false;
	bool timed_out = false;
};

class Notices {
public:
	static constexpr size_t kMaxToasts = 3;
	// How long Allow stays inert after a prompt appears.
	static constexpr uint64_t kArmUs = 1000000;

	// `now_us` is gdp::monotonic_us() throughout.
	void toast(ToastSpec spec, uint64_t now_us);
	// Takes down the toast with this tag, if one is up.
	void hide(const std::string &tag);
	void clear_toasts();

	// Queues a prompt; returns its id, which its PromptAnswer carries.
	uint64_t prompt(PromptSpec spec, uint64_t now_us);
	// Withdraws a prompt (shown or queued) without an answer: the host
	// cancelled the request.
	void cancel(uint64_t id);
	bool prompt_visible() const { return !prompts_.empty(); }
	// Answers given since the last call, in order.
	std::vector<PromptAnswer> take_answers();

	// Retires timed-out toasts and prompts and reports whether anything
	// on screen changed since the last call (an expiry, a fade step, the
	// countdown's second, Allow arming): the caller redraws then, since an
	// idle desktop sends no frame that would.
	bool tick(uint64_t now_us);

	// Keys go here first while prompt_visible(); always consumed then.
	void handle_key(SDL_Scancode scancode, uint64_t now_us);
	// Pointer in window pixels. Returns true if the pointer is over a
	// notice (or anywhere, while a prompt is up): the caller then shows
	// the local cursor and forwards nothing.
	bool handle_pointer_motion(float x, float y);
	// The pointer left the window, or is captured.
	void handle_pointer_left();
	// Returns true if the press was spectre's (on a notice, or anywhere
	// while a prompt is up) and must not be forwarded.
	bool handle_pointer_press(float x, float y, uint64_t now_us);

	// Appends the notices in the `win_w` x `win_h` window, whose video
	// starts `top` window pixels down (below the docked toolbar).
	void build(UiDrawList &out, const UiFont &font, int win_w, int win_h, float top, uint64_t now_us) const;

	size_t toast_count() const { return toasts_.size(); }

private:
	struct Toast {
		uint64_t id = 0;
		ToastSpec spec;
		uint64_t shown_us = 0;
		uint64_t remaining_us = 0; // counts down only while not hovered
		uint64_t last_us = 0;
	};
	struct Prompt {
		uint64_t id = 0;
		PromptSpec spec;
		uint64_t shown_us = 0; // 0 while queued behind another
	};
	struct Rect {
		float x = 0, y = 0, w = 0, h = 0;
		bool contains(float px, float py) const { return px >= x && px < x + w && py >= y && py < y + h; }
	};
	enum class Button { kNone, kAllow, kDeny };

	void answer(bool allowed, bool timed_out);
	void show_next_prompt(uint64_t now_us);
	bool armed(uint64_t now_us) const;
	Button button_at(float x, float y) const;

	std::deque<Toast> toasts_; // newest first
	std::deque<Prompt> prompts_;
	std::vector<PromptAnswer> answers_;
	uint64_t next_id_ = 1;
	uint64_t hovered_toast_ = 0;
	Button hovered_button_ = Button::kNone;
	// What tick() last saw, to tell whether a redraw is due.
	int64_t last_countdown_s_ = -1;
	bool last_armed_ = false;
	bool fading_ = false;
	// Set by anything that changes what's on screen; tick() reports it.
	bool dirty_ = false;
	// The latest time any call was given, for calls that take none.
	uint64_t now_us_ = 0;

	// The last build()'s layout, for hit testing.
	mutable std::vector<std::pair<uint64_t, Rect>> toast_rects_;
	mutable Rect allow_rect_, deny_rect_;
};

// Breaks `text` into lines no wider than `max_w` at `scale`, at spaces and
// at '\n'. A single word wider than `max_w` gets a line of its own.
std::vector<std::string> wrap_text(const UiFont &font, const std::string &text, float max_w, float scale);

} // namespace spectre
