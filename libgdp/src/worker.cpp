// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/worker.hpp"

#include "transport/event_queue.hpp"

#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

namespace gdp {

// What the thread and the owner share: the thread holds it too, so a
// Worker destroyed while work is under way leaves it alive until the work
// is done.
struct Worker::Shared {
	std::mutex mutex;
	std::condition_variable wake;
	std::deque<std::function<void()>> jobs;
	bool stopping = false;
	EventQueue done;
};

Worker::Worker() : shared_(std::make_shared<Shared>()) {
	std::thread([shared = shared_] {
		for (;;) {
			std::function<void()> job;
			{
				std::unique_lock<std::mutex> lock(shared->mutex);
				shared->wake.wait(lock, [&] { return shared->stopping || !shared->jobs.empty(); });
				if (shared->stopping) {
					return;
				}
				job = std::move(shared->jobs.front());
				shared->jobs.pop_front();
			}
			job();
		}
	}).detach();
}

Worker::~Worker() {
	std::deque<std::function<void()>> dropped;
	{
		std::lock_guard<std::mutex> lock(shared_->mutex);
		shared_->stopping = true;
		dropped.swap(shared_->jobs);
	}
	shared_->wake.notify_one();
	shared_->done.clear();
	// What is still under way hands back into a queue nobody drains; the
	// thread frees it when it finishes.
}

void Worker::post(std::function<void()> work, std::function<void()> then) {
	uint64_t id = next_job_++;
	thens_[id] = std::move(then);
	// Only `work` and the job's number cross over; what comes back runs from
	// dispatch(), while this Worker is there to run it.
	auto job = [shared = shared_.get(), work = std::move(work), id, this] {
		work();
		shared->done.post([this, id] {
			auto it = thens_.find(id);
			if (it == thens_.end()) {
				return;
			}
			std::function<void()> then = std::move(it->second);
			thens_.erase(it);
			if (then) {
				then();
			}
		});
	};
	{
		std::lock_guard<std::mutex> lock(shared_->mutex);
		shared_->jobs.push_back(std::move(job));
	}
	shared_->wake.notify_one();
}

int Worker::notify_fd() const {
	return shared_->done.fd();
}

void Worker::dispatch() {
	shared_->done.drain();
}

} // namespace gdp
