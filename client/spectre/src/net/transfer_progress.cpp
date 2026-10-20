// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/transfer_progress.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <iterator>

namespace spectre {

namespace {

std::string files_text(size_t n) {
	return n == 1 ? "1 file" : std::to_string(n) + " files";
}

} // namespace

double UploadProgress::fraction() const {
	if (bytes > 0) {
		return std::min(1.0, (double)done / (double)bytes);
	}
	// Nothing but empty files: by count.
	size_t counted = files - failed;
	return counted == 0 ? 0.0 : (double)sent / (double)counted;
}

void TransferRate::sample(uint64_t now_us, uint64_t done) {
	if (!samples_.empty() && now_us < samples_.back().us + 100000) {
		samples_.back().done = std::max(samples_.back().done, done);
		return;
	}
	samples_.push_back({now_us, done});
	// Keep one sample at or past the window's start, to measure from.
	while (samples_.size() > 2 && now_us - samples_[1].us >= kWindowUs) {
		samples_.pop_front();
	}
}

double TransferRate::bytes_per_s() const {
	if (samples_.size() < 2) {
		return 0.0;
	}
	const Sample &a = samples_.front(), &b = samples_.back();
	uint64_t span = b.us - a.us;
	if (span < kMinSpanUs || b.done < a.done) {
		return 0.0;
	}
	return (double)(b.done - a.done) * 1e6 / (double)span;
}

std::string format_size(uint64_t bytes) {
	if (bytes < 1000) {
		return std::to_string(bytes) + " B";
	}
	static const char *const kUnits[] = {"KB", "MB", "GB", "TB"};
	double v = (double)bytes / 1000.0;
	size_t unit = 0;
	// Rounded as it will print: 999.7 KB reads "1.0 MB", not "1000 KB".
	while (unit + 1 < std::size(kUnits) && v >= 999.5) {
		v /= 1000.0;
		unit++;
	}
	char buf[32];
	if (v < 99.95) {
		std::snprintf(buf, sizeof buf, "%.1f %s", v, kUnits[unit]);
	} else {
		std::snprintf(buf, sizeof buf, "%.0f %s", v, kUnits[unit]);
	}
	return buf;
}

std::string format_duration(uint64_t seconds) {
	char buf[32];
	uint64_t h = seconds / 3600, m = seconds / 60 % 60, s = seconds % 60;
	if (h > 0) {
		std::snprintf(buf, sizeof buf, "%llu:%02llu:%02llu", (unsigned long long)h, (unsigned long long)m,
			(unsigned long long)s);
	} else {
		std::snprintf(buf, sizeof buf, "%llu:%02llu", (unsigned long long)m, (unsigned long long)s);
	}
	return buf;
}

ProgressSpec upload_card(const UploadProgress &p, double rate_bps) {
	ProgressSpec spec;
	size_t counted = p.files - p.failed;
	spec.title = counted <= 1 ? "Sending to the host" : "Sending " + files_text(counted) + " to the host";
	spec.detail = p.current;
	size_t others = p.remaining() > 0 ? p.remaining() - 1 : 0;
	if (!spec.detail.empty() && others > 0) {
		spec.detail += " and " + std::to_string(others) + " more";
	}
	spec.figures = format_size(p.done) + " of " + format_size(p.bytes);
	if (rate_bps > 0) {
		spec.figures += ", " + format_size((uint64_t)rate_bps) + "/s";
		if (p.bytes > p.done) {
			spec.figures +=
				", " + format_duration((uint64_t)std::ceil((double)(p.bytes - p.done) / rate_bps)) + " left";
		}
	}
	spec.fraction = p.fraction();
	return spec;
}

ToastSpec upload_summary(const UploadProgress &p) {
	ToastSpec spec;
	spec.duration_us = 5000000;
	if (p.cancelled > 0) {
		spec.level = NoticeLevel::kWarning;
		spec.title = "Cancelled sending " + (p.files == 1 ? p.first : files_text(p.files - p.failed));
		if (p.sent > 0) {
			spec.body = "Sent " + std::to_string(p.sent) + " of " + std::to_string(p.files - p.failed) +
				" before that";
		}
		return spec;
	}
	if (p.sent == 0) {
		return spec; // every one failed, and said so
	}
	if (p.failed > 0) {
		spec.level = NoticeLevel::kWarning;
		spec.title = "Sent " + std::to_string(p.sent) + " of " + files_text(p.files);
		spec.body = files_text(p.failed) + (p.failed == 1 ? " wasn't" : " weren't") + " sent";
		return spec;
	}
	spec.level = NoticeLevel::kSuccess;
	spec.title = p.files == 1 ? "Sent " + p.first : "Sent " + files_text(p.sent);
	if (!p.where.empty()) {
		spec.title += " to " + p.where;
	}
	spec.duration_us = 4000000;
	return spec;
}

} // namespace spectre
