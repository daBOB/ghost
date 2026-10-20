// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// What a batch of uploads (net/file_transfers.hpp) has done, and the words
// for it on spectre's progress card and the toast that follows it
// (ui/notices.hpp). Pure: no streams, no clock of its own, so it is tested
// on its own (tests/transfer_progress_test.cpp).
#pragma once

#include "ui/notices.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>

namespace spectre {

// A batch: every file dropped while an earlier one was still going joins
// the batch it was going in.
struct UploadProgress {
	size_t files = 0;     // offered in the batch
	size_t sent = 0;      // saved by the host
	size_t failed = 0;    // refused or failed (each said so on its own)
	size_t cancelled = 0; // still open or queued when the user cancelled
	// Bytes of every file not failed, and how many of them the host has
	// acknowledged; a saved file counts whole.
	uint64_t bytes = 0;
	uint64_t done = 0;
	std::string first;   // the batch's first file: its name, when it is the only one
	std::string current; // the oldest file still going, empty once none is
	std::string where;   // the host's folder for the last file saved

	size_t remaining() const { return files - sent - failed - cancelled; }
	double fraction() const;
};

// Bytes per second over the last few seconds of samples.
class TransferRate {
public:
	static constexpr uint64_t kWindowUs = 3000000;
	// No figure until the samples span this long.
	static constexpr uint64_t kMinSpanUs = 1000000;

	// `done` is UploadProgress::done, which only grows within a batch.
	void sample(uint64_t now_us, uint64_t done);
	void reset() { samples_.clear(); }
	// 0 while unknown.
	double bytes_per_s() const;

private:
	struct Sample {
		uint64_t us, done;
	};
	std::deque<Sample> samples_;
};

// "512 B", "12.3 KB", "192 MB", "1.4 GB": powers of 1000, as file
// managers show them.
std::string format_size(uint64_t bytes);
// "0:07", "12:30", "1:02:03".
std::string format_duration(uint64_t seconds);

// The card for `p`, at `rate_bps` (0: unknown, no speed or time left).
ProgressSpec upload_card(const UploadProgress &p, double rate_bps);

// The toast once the batch is over; an empty title when there is nothing
// left to say (every file failed, and each failure had its own toast).
ToastSpec upload_summary(const UploadProgress &p);

} // namespace spectre
