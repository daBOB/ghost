// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// Worker: a thread of its own for work that may wait on the disk -- reading
// a folder or a file on a slow or network drive -- so that the loop which
// owns it (wraith's, encoding the desktop; spectre's, showing it) never
// does. Work runs on the worker's thread one at a time, in order; what
// comes of it is handed back on the owner's thread, from dispatch(), the
// way gdp::Transport hands back its events.
//
// Work must not touch the owner or anything it owns: it gets what it needs
// by value (a path, a shared_ptr to an open file), and may be destroyed on
// the worker's thread. `then` never leaves the owner's thread, so it may
// hold the owner's things (a stream to answer on). Destroying the Worker
// doesn't wait for work under way -- a read stuck on a hung drive would
// otherwise hold up the owner's loop -- so the thread is let go to finish
// on its own, and the `then` of what was posted is dropped unrun.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>

namespace gdp {

class Worker {
public:
	Worker();
	~Worker();
	Worker(const Worker &) = delete;
	Worker &operator=(const Worker &) = delete;

	// Runs `work` on the worker's thread, then `then` on the owner's, from
	// dispatch().
	void post(std::function<void()> work, std::function<void()> then);

	// `work`'s result handed to `then`.
	template <class Result>
	void run(std::function<Result()> work, std::function<void(Result)> then) {
		auto result = std::make_shared<Result>();
		post([result, work = std::move(work)] { *result = work(); },
			[result, then = std::move(then)] { then(std::move(*result)); });
	}

	// Becomes readable whenever dispatch() has something to hand back. -1 on
	// Windows, where the owner calls dispatch() on every pass of its loop.
	int notify_fd() const;
	void dispatch();

	// Posted, and not yet handed back: for tests and logs.
	size_t pending() const { return thens_.size(); }

	struct Shared;

private:
	std::shared_ptr<Shared> shared_;
	std::map<uint64_t, std::function<void()>> thens_; // by job, owner's thread only
	uint64_t next_job_ = 1;
};

} // namespace gdp
