// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/host_file_reads.hpp"

#include "gdp/clock.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace spectre {

namespace {

constexpr uint64_t kReplyTimeoutUs = gdp::kFileReplyTimeoutMs * 1000ull;

class StreamChannel : public HostFileReads::Channel {
public:
	explicit StreamChannel(std::unique_ptr<gdp::Stream> stream) : stream_(std::move(stream)) {}
	void consume(size_t n) override { stream_->consume(n); }
	void cancel() override { stream_->reset(0); }

private:
	std::unique_ptr<gdp::Stream> stream_;
};

} // namespace

struct HostFileReads::Request {
	std::shared_ptr<Shared> shared;
	std::unique_ptr<Channel> channel;
	uint64_t deadline_us = 0;      // waiting for the reply until then; 0 once it came
	uint64_t last_progress_us = 0; // when bytes last came or were taken
	// A file's bytes: one FileReply, then raw bytes.
	gdp::FrameThenRawReader reader{gdp::kMaxFileOpenFrameSize};
	uint64_t fed = 0;
	bool replied = false;
	uint64_t skip = 0; // bytes before the offset that a host ignoring ranges sends
	uint64_t size = 0;
	uint64_t received = 0;
	// A listing: FileReply frames until FIN.
	gdp::FrameReader frames;
};

HostFileReads::Read::~Read() {
	std::lock_guard<std::mutex> lock(shared_->mutex);
	shared_->cancelled = true;
}

int64_t HostFileReads::Read::read(uint8_t *buf, size_t n, uint32_t timeout_ms) {
	Shared &s = *shared_;
	std::unique_lock<std::mutex> lock(s.mutex);
	s.changed.wait_for(lock, std::chrono::milliseconds(timeout_ms),
		[&] { return s.head < s.bytes.size() || s.ended || s.failed; });
	if (s.head < s.bytes.size()) {
		// What came before a failure is still the file's: it goes first.
		size_t k = std::min(n, s.bytes.size() - s.head);
		std::memcpy(buf, s.bytes.data() + s.head, k);
		s.head += k;
		s.taken += k;
		if (s.head == s.bytes.size()) {
			s.bytes.clear();
			s.head = 0;
		}
		return static_cast<int64_t>(k);
	}
	return s.ended && !s.failed ? 0 : -1;
}

bool HostFileReads::Read::listing(std::vector<gdp::session::FileListing> *frames, uint32_t timeout_ms) {
	Shared &s = *shared_;
	std::unique_lock<std::mutex> lock(s.mutex);
	s.changed.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] { return s.ended || s.failed; });
	if (!s.ended || s.failed) {
		return false;
	}
	*frames = std::move(s.frames);
	s.frames.clear();
	return true;
}

HostFileReads::HostFileReads(Requester requester, std::function<uint64_t()> now_us)
	: requester_(std::move(requester)), now_us_(now_us ? std::move(now_us) : gdp::monotonic_us) {}

HostFileReads::~HostFileReads() {
	close();
}

std::unique_ptr<HostFileReads::Read> HostFileReads::post(const Target &target, uint64_t offset) {
	auto shared = std::make_shared<Shared>();
	shared->target = target;
	shared->offset = offset;
	std::lock_guard<std::mutex> lock(posted_mutex_);
	if (closed_) {
		shared->failed = true;
	} else {
		posted_.push_back(shared);
	}
	return std::make_unique<Read>(std::move(shared));
}

std::unique_ptr<HostFileReads::Read> HostFileReads::post_listing(const Target &target) {
	auto shared = std::make_shared<Shared>();
	shared->target = target;
	shared->is_listing = true;
	std::lock_guard<std::mutex> lock(posted_mutex_);
	if (closed_) {
		shared->failed = true;
	} else {
		posted_.push_back(shared);
	}
	return std::make_unique<Read>(std::move(shared));
}

void HostFileReads::dispatch() {
	std::vector<std::shared_ptr<Shared>> posted;
	{
		std::lock_guard<std::mutex> lock(posted_mutex_);
		posted.swap(posted_);
	}
	uint64_t now = now_us_();
	for (std::shared_ptr<Shared> &shared : posted) {
		{
			std::lock_guard<std::mutex> lock(shared->mutex);
			if (shared->cancelled) {
				continue; // let go before it was asked for
			}
		}
		uint64_t id = next_id_++;
		auto req = std::make_unique<Request>();
		req->shared = shared;
		req->deadline_us = now + kReplyTimeoutUs;
		req->last_progress_us = now;
		requests_[id] = std::move(req);
		// Before asking: a request can fail at once.
		requester_(id, shared->target, shared->offset, shared->is_listing);
	}

	std::vector<uint64_t> cancelled;
	for (auto &[id, req] : requests_) {
		size_t taken = 0;
		{
			std::lock_guard<std::mutex> lock(req->shared->mutex);
			if (req->shared->cancelled) {
				cancelled.push_back(id);
				continue;
			}
			taken = req->shared->taken;
			req->shared->taken = 0;
		}
		if (taken > 0) {
			req->last_progress_us = now;
			if (req->channel) {
				req->channel->consume(taken);
			}
		}
	}
	for (uint64_t id : cancelled) {
		auto it = requests_.find(id);
		if (it->second->channel) {
			it->second->channel->cancel();
		}
		requests_.erase(it);
	}
}

void HostFileReads::tick(uint64_t now_us) {
	std::vector<uint64_t> late;
	for (const auto &[id, req] : requests_) {
		if (req->deadline_us != 0) {
			if (now_us >= req->deadline_us) {
				late.push_back(id);
			}
			continue;
		}
		if (now_us < req->last_progress_us + kReplyTimeoutUs) {
			continue;
		}
		// Silent this long: late if its reader is waiting on it, not just
		// slow to take what came.
		std::lock_guard<std::mutex> lock(req->shared->mutex);
		if (req->shared->is_listing || req->shared->head == req->shared->bytes.size()) {
			late.push_back(id);
		}
	}
	for (uint64_t id : late) {
		auto it = requests_.find(id);
		if (it != requests_.end() && it->second->channel) {
			it->second->channel->cancel();
		}
		finish(id, false);
	}
}

void HostFileReads::close() {
	std::vector<std::shared_ptr<Shared>> posted;
	{
		std::lock_guard<std::mutex> lock(posted_mutex_);
		closed_ = true;
		posted.swap(posted_);
	}
	for (std::shared_ptr<Shared> &shared : posted) {
		std::lock_guard<std::mutex> lock(shared->mutex);
		shared->failed = true;
		shared->changed.notify_all();
	}
	while (!requests_.empty()) {
		auto it = requests_.begin();
		if (it->second->channel) {
			it->second->channel->cancel();
		}
		finish(it->first, false);
	}
}

void HostFileReads::answer(uint64_t id, std::unique_ptr<gdp::Stream> stream) {
	gdp::Stream *s = stream.get();
	auto it = requests_.find(id);
	if (it == requests_.end() || it->second->channel) {
		stream->reset(0); // given up on, or answered twice
		return;
	}
	s->on_data = [this, id](const uint8_t *d, size_t len) { data(id, d, len); };
	s->on_fin = [this, id] { fin(id); };
	s->on_reset = [this, id](uint64_t) { reset(id); };
	it->second->channel = std::make_unique<StreamChannel>(std::move(stream));
}

void HostFileReads::answer(uint64_t id, std::unique_ptr<Channel> channel) {
	auto it = requests_.find(id);
	if (it == requests_.end() || it->second->channel) {
		channel->cancel();
		return;
	}
	it->second->channel = std::move(channel);
}

void HostFileReads::fail(uint64_t id) {
	finish(id, false);
}

void HostFileReads::data(uint64_t id, const uint8_t *bytes, size_t len) {
	auto it = requests_.find(id);
	if (it == requests_.end()) {
		return;
	}
	Request &req = *it->second;
	Shared &shared = *req.shared;
	req.last_progress_us = now_us_();

	if (shared.is_listing) {
		if (req.channel) {
			req.channel->consume(len);
		}
		gdp::session::FileReply reply;
		bool refused = false;
		std::vector<gdp::session::FileListing> got;
		bool ok = req.frames.feed_and_drain(bytes, len, &reply, [&] {
			req.deadline_us = 0;
			if (!reply.has_listing()) {
				refused = true; // refused, or not a listing at all
				return false;
			}
			got.push_back(std::move(*reply.mutable_listing()));
			return true;
		});
		if (!ok || refused) {
			finish(id, false);
			return;
		}
		std::lock_guard<std::mutex> lock(shared.mutex);
		for (gdp::session::FileListing &l : got) {
			shared.frames.push_back(std::move(l));
		}
		return;
	}

	req.fed += len;
	gdp::FrameThenRawReader::State state = req.reader.feed(bytes, len);
	if (state == gdp::FrameThenRawReader::State::kError) {
		finish(id, false);
		return;
	}
	if (state != gdp::FrameThenRawReader::State::kFramed) {
		return;
	}
	std::vector<uint8_t> raw = req.reader.take_data();
	if (!req.replied) {
		req.replied = true;
		req.deadline_us = 0;
		if (req.channel) {
			req.channel->consume(static_cast<size_t>(req.fed - raw.size())); // the reply frame
		}
		gdp::session::FileReply reply;
		if (!reply.ParseFromString(req.reader.frame()) || !reply.has_sending() ||
			reply.sending().offset() > shared.offset) {
			finish(id, false); // refused, or not what was asked for
			return;
		}
		// A host from before ranges sends the whole file from 0 (§7.12).
		req.skip = shared.offset - reply.sending().offset();
		if (req.skip > reply.sending().size()) {
			finish(id, false);
			return;
		}
		req.size = reply.sending().size() - req.skip;
	}
	size_t at = 0;
	if (req.skip > 0) {
		size_t n = static_cast<size_t>(std::min<uint64_t>(req.skip, raw.size()));
		req.skip -= n;
		at = n;
		if (req.channel) {
			req.channel->consume(n);
		}
	}
	size_t n = raw.size() - at;
	if (n == 0) {
		return;
	}
	if (req.received + n > req.size) {
		finish(id, false); // more than it said
		return;
	}
	req.received += n;
	std::lock_guard<std::mutex> lock(shared.mutex);
	if (shared.head > 0 && shared.head >= shared.bytes.size() / 2) {
		shared.bytes.erase(shared.bytes.begin(), shared.bytes.begin() + static_cast<ptrdiff_t>(shared.head));
		shared.head = 0;
	}
	shared.bytes.insert(shared.bytes.end(), raw.begin() + static_cast<ptrdiff_t>(at), raw.end());
	shared.changed.notify_all();
}

void HostFileReads::fin(uint64_t id) {
	auto it = requests_.find(id);
	if (it == requests_.end()) {
		return;
	}
	const Request &req = *it->second;
	if (req.shared->is_listing) {
		finish(id, req.deadline_us == 0); // at least one frame
	} else {
		finish(id, req.replied && req.skip == 0 && req.received == req.size);
	}
}

void HostFileReads::reset(uint64_t id) {
	finish(id, false);
}

void HostFileReads::finish(uint64_t id, bool ok) {
	auto it = requests_.find(id);
	if (it == requests_.end()) {
		return;
	}
	std::unique_ptr<Request> req = std::move(it->second);
	requests_.erase(it);
	{
		std::lock_guard<std::mutex> lock(req->shared->mutex);
		req->shared->ended = true;
		req->shared->failed = !ok;
		req->shared->changed.notify_all();
	}
	// The channel goes with the request: gracefully once the host finished,
	// else reset.
}

} // namespace spectre
