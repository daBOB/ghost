// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

// gdp::Worker: work runs off the owner's thread, in order, and comes back
// on it from dispatch(); and destroying a Worker whose work is stuck
// returns at once, dropping what it would have handed back.
#include "gdp/worker.hpp"

#undef NDEBUG
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <poll.h>
#endif

namespace {

// Dispatches until `done`, waiting on notify_fd() where there is one.
bool spin(gdp::Worker &worker, const std::function<bool()> &done) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	while (!done()) {
		if (std::chrono::steady_clock::now() > deadline) {
			return false;
		}
#ifndef _WIN32
		struct pollfd pfd = {worker.notify_fd(), POLLIN, 0};
		poll(&pfd, 1, 10);
#else
		std::this_thread::sleep_for(std::chrono::milliseconds(1));
#endif
		worker.dispatch();
	}
	return true;
}

} // namespace

int main() {
	const std::thread::id owner = std::this_thread::get_id();

	{
		gdp::Worker worker;
		std::vector<int> order;
		std::atomic<bool> off_thread{true};
		for (int i = 0; i < 5; i++) {
			worker.run<int>(
				[i, owner, &off_thread] {
					if (std::this_thread::get_id() == owner) {
						off_thread = false;
					}
					return i * 10;
				},
				[i, owner, &order](int result) {
					assert(std::this_thread::get_id() == owner);
					assert(result == i * 10);
					order.push_back(i);
				});
		}
		assert(worker.pending() == 5);
		assert(spin(worker, [&] { return order.size() == 5; }));
		assert(off_thread);
		assert((order == std::vector<int>{0, 1, 2, 3, 4}));
		assert(worker.pending() == 0);
		// Nothing runs without dispatch().
		bool ran = false;
		std::atomic<bool> worked{false};
		worker.post([&] { worked = true; }, [&] { ran = true; });
		while (!worked) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
		assert(!ran);
		assert(spin(worker, [&] { return ran; }));
	}

	// Stuck work (a hung drive): destroying the Worker doesn't wait for it,
	// and its `then` never runs.
	auto release = std::make_shared<std::atomic<bool>>(false);
	auto started = std::make_shared<std::atomic<bool>>(false);
	auto finished = std::make_shared<std::atomic<bool>>(false);
	bool then_ran = false;
	std::chrono::steady_clock::time_point start;
	{
		gdp::Worker worker;
		worker.post(
			[release, started, finished] {
				*started = true;
				while (!*release) {
					std::this_thread::sleep_for(std::chrono::milliseconds(5));
				}
				*finished = true;
			},
			[&] { then_ran = true; });
		worker.post([] {}, [&] { then_ran = true; }); // queued behind it: dropped
		while (!*started) {
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		start = std::chrono::steady_clock::now();
	}
	assert(std::chrono::steady_clock::now() - start < std::chrono::seconds(1));
	*release = true;
	while (!*finished) {
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(20)); // it hands back into nothing
	assert(!then_ran);

	printf("worker_test: all passed\n");
	return 0;
}
