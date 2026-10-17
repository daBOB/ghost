// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: MIT

#include "gdp/remote_mount.hpp"

#ifdef GDP_HAVE_FUSE

#define FUSE_USE_VERSION 312
#include <fuse_lowlevel.h>

#include "gdp/clock.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>

#include <poll.h>
#include <spawn.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace gdp {

namespace {

// Every mount of this process's, as named and as the real path, for
// inside_own_mount().
std::mutex g_mounts_mutex;
std::vector<std::string> g_mounts;

bool under_path(const std::string &path, const std::string &dir) {
	return path.compare(0, dir.size(), dir) == 0 && (path.size() == dir.size() || path[dir.size()] == '/');
}

// `directory`'s names, worked out before it is mounted (realpath() of a
// mount would ask it), and registered.
std::vector<std::string> register_mount(const std::string &directory) {
	std::vector<std::string> names = {directory};
	if (char *real = realpath(directory.c_str(), nullptr)) {
		if (directory != real) {
			names.push_back(real);
		}
		free(real);
	}
	std::lock_guard<std::mutex> lock(g_mounts_mutex);
	g_mounts.insert(g_mounts.end(), names.begin(), names.end());
	return names;
}

void unregister_mount(const std::vector<std::string> &names) {
	std::lock_guard<std::mutex> lock(g_mounts_mutex);
	for (const std::string &name : names) {
		auto it = std::find(g_mounts.begin(), g_mounts.end(), name);
		if (it != g_mounts.end()) {
			g_mounts.erase(it);
		}
	}
}

// What the kernel keeps of an entry that never changes (a copied file).
constexpr double kForeverSeconds = 3600;
// How far past what a range has brought a read may be and still wait for
// it, rather than open a range of its own: the kernel's read-ahead asks a
// little ahead of where the copy is.
constexpr uint64_t kWaitAheadBytes = 2ull << 20;

} // namespace

struct RemoteMount::Impl {
	struct Op {
		enum Type { kLookup, kGetattr, kOpendir, kReaddir, kReleasedir, kOpen, kRead, kRelease, kStatfs } type;
		fuse_req_t req = nullptr;
		Node ino = 0;
		std::string name;
		size_t size = 0;
		uint64_t off = 0;
		uint64_t fh = 0;
	};

	struct NodeData {
		Node parent = 0;
		Entry entry;
		std::vector<Node> children;
		bool listing = false; // on_list asked, no answer yet
		uint64_t listed_us = 0;
		std::vector<Op> waiting; // lookups and opendirs waiting for the listing
	};

	struct Read {
		fuse_req_t req;
		uint64_t off;
		size_t size;
	};

	struct OpenFile {
		Node node = 0;
		uint64_t key = 0;
		uint64_t size = 0;
		uint64_t range = 0;   // 0: none open
		bool range_done = false;
		int error = 0;        // what the range ended with
		uint64_t buf_off = 0; // the file offset buf[0] is at
		std::vector<uint8_t> buf;
		uint64_t served_to = 0;
		std::deque<Read> pending;
		bool dead = false; // its node was removed
	};

	RemoteMount *owner = nullptr;
	struct fuse_session *se = nullptr;
	std::vector<std::string> names; // register_mount()'s
	std::thread loop;
	int wake_fd = -1; // owner: requests waiting
	int stop_fd = -1; // loop: stop
	std::mutex mutex;
	std::deque<Op> ops;

	std::unordered_map<Node, NodeData> nodes;
	Node next_node = kRoot + 1;
	std::unordered_map<uint64_t, OpenFile> files;
	uint64_t next_fh = 1;
	std::unordered_map<uint64_t, uint64_t> ranges; // range -> fh
	uint64_t next_range = 1;
	uint64_t ranges_opened = 0;
	uid_t uid = getuid();
	gid_t gid = getgid();

	// --- FUSE's thread: hand each request over ---

	static Impl *of(fuse_req_t req) { return static_cast<Impl *>(fuse_req_userdata(req)); }

	void post(Op op) {
		{
			std::lock_guard<std::mutex> lock(mutex);
			ops.push_back(std::move(op));
		}
		uint64_t one = 1;
		ssize_t ignored = write(wake_fd, &one, sizeof(one));
		(void)ignored;
	}

	static Op make(Op::Type type, fuse_req_t req, fuse_ino_t ino) {
		Op op;
		op.type = type;
		op.req = req;
		op.ino = ino;
		return op;
	}

	static void ll_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
		Op op = make(Op::kLookup, req, parent);
		op.name = name;
		of(req)->post(std::move(op));
	}
	static void ll_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *) {
		of(req)->post(make(Op::kGetattr, req, ino));
	}
	static void ll_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *) {
		of(req)->post(make(Op::kOpendir, req, ino));
	}
	static void ll_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *) {
		Op op = make(Op::kReaddir, req, ino);
		op.size = size;
		op.off = static_cast<uint64_t>(off);
		of(req)->post(std::move(op));
	}
	static void ll_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *) {
		of(req)->post(make(Op::kReleasedir, req, ino));
	}
	static void ll_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
		if ((fi->flags & O_ACCMODE) != O_RDONLY) {
			fuse_reply_err(req, EROFS);
			return;
		}
		of(req)->post(make(Op::kOpen, req, ino));
	}
	static void ll_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
		Op op = make(Op::kRead, req, ino);
		op.size = size;
		op.off = static_cast<uint64_t>(off);
		op.fh = fi->fh;
		of(req)->post(std::move(op));
	}
	static void ll_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
		Op op = make(Op::kRelease, req, ino);
		op.fh = fi->fh;
		of(req)->post(std::move(op));
	}
	static void ll_statfs(fuse_req_t req, fuse_ino_t ino) { of(req)->post(make(Op::kStatfs, req, ino)); }
	static void ll_forget(fuse_req_t req, fuse_ino_t, uint64_t) { fuse_reply_none(req); }
	static void ll_forget_multi(fuse_req_t req, size_t, struct fuse_forget_data *) { fuse_reply_none(req); }

	void loop_main() {
		struct fuse_buf buf = {};
		struct pollfd fds[2] = {{fuse_session_fd(se), POLLIN, 0}, {stop_fd, POLLIN, 0}};
		while (!fuse_session_exited(se)) {
			if (poll(fds, 2, -1) < 0) {
				if (errno == EINTR) {
					continue;
				}
				break;
			}
			if (fds[1].revents) {
				break;
			}
			if (!(fds[0].revents & POLLIN)) {
				if (fds[0].revents & (POLLERR | POLLHUP)) {
					break;
				}
				continue;
			}
			int r = fuse_session_receive_buf(se, &buf);
			if (r == -EINTR || r == -EAGAIN) {
				continue;
			}
			if (r <= 0) {
				break; // unmounted underneath us (ENODEV), or an error
			}
			fuse_session_process_buf(se, &buf);
		}
		free(buf.mem);
	}

	// --- the owner's thread ---

	struct stat attr_of(Node node, const Entry &e) const {
		struct stat st = {};
		st.st_ino = node;
		// The usual modes, not read-only ones: a copy keeps the mode, and a
		// pasted folder its user can't write into is no use. The mount is
		// read-only all the same (EROFS).
		st.st_mode = e.directory ? (S_IFDIR | 0755) : (S_IFREG | 0644);
		st.st_nlink = e.directory ? 2 : 1;
		st.st_size = e.directory ? 0 : static_cast<off_t>(e.size);
		st.st_blocks = (st.st_size + 511) / 512;
		st.st_blksize = 128 * 1024;
		st.st_uid = uid;
		st.st_gid = gid;
		st.st_mtim.tv_sec = e.modified_unix_ms / 1000;
		st.st_mtim.tv_nsec = (e.modified_unix_ms % 1000) * 1000000;
		st.st_ctim = st.st_atim = st.st_mtim;
		return st;
	}

	static double cache_seconds(const Entry &e) { return e.refresh_seconds > 0 ? e.refresh_seconds : kForeverSeconds; }

	NodeData *node(Node n) {
		auto it = nodes.find(n);
		return it == nodes.end() ? nullptr : &it->second;
	}

	// Whether `folder`'s contents must be asked for before answering.
	bool needs_listing(const NodeData &folder) const {
		if (!folder.entry.listed) {
			return true;
		}
		double refresh = folder.entry.refresh_seconds;
		return refresh > 0 && monotonic_us() - folder.listed_us > static_cast<uint64_t>(refresh * 1e6);
	}

	void wait_for_listing(Node folder_node, NodeData &folder, Op op) {
		folder.waiting.push_back(std::move(op));
		if (!folder.listing) {
			folder.listing = true;
			if (owner->on_list) {
				owner->on_list(folder_node, folder.entry.key);
			} else {
				owner->fail_children(folder_node, EIO);
			}
		}
	}

	void handle(Op &op) {
		static const bool trace = getenv("GDP_FUSE_TRACE") != nullptr;
		if (trace) {
			fprintf(stderr, "fuse: op %d ino %llu name '%s' off %llu size %zu fh %llu\n", (int)op.type,
				(unsigned long long)op.ino, op.name.c_str(), (unsigned long long)op.off, op.size,
				(unsigned long long)op.fh);
		}
		switch (op.type) {
		case Op::kLookup: lookup(op); break;
		case Op::kGetattr: {
			NodeData *n = node(op.ino);
			if (!n) {
				fuse_reply_err(op.req, ENOENT);
				break;
			}
			struct stat st = attr_of(op.ino, n->entry);
			fuse_reply_attr(op.req, &st, cache_seconds(n->entry));
			break;
		}
		case Op::kOpendir: {
			NodeData *n = node(op.ino);
			if (!n || !n->entry.directory) {
				fuse_reply_err(op.req, n ? ENOTDIR : ENOENT);
				break;
			}
			if (needs_listing(*n)) {
				wait_for_listing(op.ino, *n, op);
				break;
			}
			struct fuse_file_info fi = {};
			fuse_reply_open(op.req, &fi);
			break;
		}
		case Op::kReaddir: readdir(op); break;
		case Op::kReleasedir: fuse_reply_err(op.req, 0); break;
		case Op::kOpen: open(op); break;
		case Op::kRead: read(op); break;
		case Op::kRelease: release(op); break;
		case Op::kStatfs: {
			struct statvfs st = {};
			st.f_bsize = st.f_frsize = 128 * 1024;
			st.f_namemax = 255;
			fuse_reply_statfs(op.req, &st);
			break;
		}
		}
	}

	void lookup(Op &op) {
		NodeData *parent = node(op.ino);
		if (!parent || !parent->entry.directory) {
			fuse_reply_err(op.req, parent ? ENOTDIR : ENOENT);
			return;
		}
		Node found = owner->child(op.ino, op.name);
		// A name not there may have come since a shared folder was listed.
		if (needs_listing(*parent) && (!found || !parent->entry.listed)) {
			wait_for_listing(op.ino, *parent, op);
			return;
		}
		if (!found) {
			struct fuse_entry_param e = {};
			e.entry_timeout = parent->entry.refresh_seconds > 0 ? parent->entry.refresh_seconds : 1;
			fuse_reply_entry(op.req, &e); // a negative entry, cached briefly
			return;
		}
		const NodeData &child = nodes.at(found);
		struct fuse_entry_param e = {};
		e.ino = found;
		e.attr = attr_of(found, child.entry);
		e.attr_timeout = e.entry_timeout = cache_seconds(child.entry);
		fuse_reply_entry(op.req, &e);
	}

	void readdir(Op &op) {
		NodeData *n = node(op.ino);
		if (!n || !n->entry.directory) {
			fuse_reply_err(op.req, n ? ENOTDIR : ENOENT);
			return;
		}
		std::vector<char> buf(op.size);
		size_t used = 0;
		size_t total = n->children.size() + 2;
		for (size_t i = op.off; i < total; i++) {
			struct stat st = {};
			const char *name;
			if (i == 0) {
				name = ".";
				st.st_ino = op.ino;
				st.st_mode = S_IFDIR;
			} else if (i == 1) {
				name = "..";
				st.st_ino = n->parent ? n->parent : op.ino;
				st.st_mode = S_IFDIR;
			} else {
				Node c = n->children[i - 2];
				const NodeData &child = nodes.at(c);
				name = child.entry.name.c_str();
				st = attr_of(c, child.entry);
			}
			size_t len = fuse_add_direntry(op.req, buf.data() + used, buf.size() - used, name, &st,
				static_cast<off_t>(i + 1));
			if (len > buf.size() - used) {
				break;
			}
			used += len;
		}
		fuse_reply_buf(op.req, buf.data(), used);
	}

	void open(Op &op) {
		NodeData *n = node(op.ino);
		if (!n || n->entry.directory) {
			fuse_reply_err(op.req, n ? EISDIR : ENOENT);
			return;
		}
		uint64_t fh = next_fh++;
		OpenFile &f = files[fh];
		f.node = op.ino;
		f.key = n->entry.key;
		f.size = n->entry.size;
		struct fuse_file_info fi = {};
		fi.fh = fh;
		fi.keep_cache = n->entry.refresh_seconds == 0; // a copy never changes
		fuse_reply_open(op.req, &fi);
	}

	void close_range(OpenFile &f) {
		if (f.range && !f.range_done && owner->on_close_range) {
			owner->on_close_range(f.range);
		}
		ranges.erase(f.range);
		f.range = 0;
	}

	void open_range(uint64_t fh, OpenFile &f, uint64_t off) {
		close_range(f);
		f.buf.clear();
		f.buf_off = off;
		f.served_to = off;
		f.range_done = false;
		f.error = 0;
		f.range = next_range++;
		ranges[f.range] = fh;
		ranges_opened++;
		if (owner->on_open_range) {
			owner->on_open_range(f.range, f.node, f.key, off);
		} else {
			owner->range_end(f.range, EIO);
		}
	}

	void read(Op &op) {
		auto it = files.find(op.fh);
		if (it == files.end()) {
			fuse_reply_err(op.req, EBADF);
			return;
		}
		OpenFile &f = it->second;
		if (f.dead) {
			fuse_reply_err(op.req, EIO);
			return;
		}
		if (op.off >= f.size || op.size == 0) {
			fuse_reply_buf(op.req, nullptr, 0);
			return;
		}
		size_t size = static_cast<size_t>(std::min<uint64_t>(op.size, f.size - op.off));
		f.pending.push_back({op.req, op.off, size});
		uint64_t have_to = f.buf_off + f.buf.size();
		bool behind = op.off < f.buf_off;
		bool too_far = f.range_done ? op.off + size > have_to : op.off > have_to + kWaitAheadBytes;
		if (!f.range || behind || too_far) {
			// From the earliest read still waiting, so none is left behind.
			uint64_t from = op.off;
			for (const Read &r : f.pending) {
				from = std::min(from, r.off);
			}
			open_range(op.fh, f, from);
		}
		serve(f);
	}

	void serve(OpenFile &f) {
		uint64_t have_to = f.buf_off + f.buf.size();
		for (auto it = f.pending.begin(); it != f.pending.end();) {
			const Read &r = *it;
			bool whole = r.off >= f.buf_off && r.off + r.size <= have_to;
			if (!whole && !(f.range_done && r.off >= f.buf_off)) {
				++it;
				continue;
			}
			if (!whole && f.error) {
				fuse_reply_err(r.req, f.error);
			} else {
				// Whole, or as much as there is: the range ended early (the
				// file shrank since it was listed).
				size_t len = r.off < have_to ? static_cast<size_t>(std::min<uint64_t>(r.size, have_to - r.off)) : 0;
				fuse_reply_buf(r.req, len ? reinterpret_cast<const char *>(f.buf.data() + (r.off - f.buf_off)) : nullptr,
					len);
				f.served_to = std::max(f.served_to, r.off + len);
			}
			it = f.pending.erase(it);
		}
		// What no read still waiting wants goes, and its credit back to the
		// sender: with reads waiting, everything before the first of them
		// (bytes skipped on the way to a read further on, or the window would
		// fill with them and stall); with none, everything served.
		uint64_t keep_from = f.served_to;
		if (!f.pending.empty()) {
			keep_from = UINT64_MAX;
			for (const Read &r : f.pending) {
				keep_from = std::min(keep_from, r.off);
			}
		}
		if (keep_from > f.buf_off) {
			size_t drop = static_cast<size_t>(std::min<uint64_t>(keep_from - f.buf_off, f.buf.size()));
			if (drop > 0) {
				f.buf.erase(f.buf.begin(), f.buf.begin() + static_cast<ptrdiff_t>(drop));
				f.buf_off += drop;
				if (f.range && !f.range_done && owner->on_consumed) {
					owner->on_consumed(f.range, drop);
				}
			}
		}
	}

	void release(Op &op) {
		auto it = files.find(op.fh);
		if (it != files.end()) {
			for (const Read &r : it->second.pending) {
				fuse_reply_err(r.req, EIO);
			}
			close_range(it->second);
			files.erase(it);
		}
		fuse_reply_err(op.req, 0);
	}

	void fail_all() {
		std::deque<Op> queued;
		{
			std::lock_guard<std::mutex> lock(mutex);
			queued.swap(ops);
		}
		for (Op &op : queued) {
			if (op.type == Op::kRelease || op.type == Op::kReleasedir) {
				fuse_reply_err(op.req, 0);
			} else {
				fuse_reply_err(op.req, EIO);
			}
		}
		for (auto &[n, data] : nodes) {
			for (Op &op : data.waiting) {
				fuse_reply_err(op.req, EIO);
			}
			data.waiting.clear();
		}
		for (auto &[fh, f] : files) {
			for (const Read &r : f.pending) {
				fuse_reply_err(r.req, EIO);
			}
			f.pending.clear();
		}
	}
};

RemoteMount::RemoteMount() : impl_(std::make_unique<Impl>()) {
	impl_->owner = this;
	Impl::NodeData root;
	root.entry.directory = true;
	root.entry.name = "";
	root.entry.modified_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::system_clock::now().time_since_epoch())
									  .count();
	impl_->nodes[kRoot] = std::move(root);
}

RemoteMount::~RemoteMount() {
	unmount();
}

bool RemoteMount::supported() {
	return true;
}

namespace {

// fusermount3 -u -z: a mount a crashed process left behind ("Transport
// endpoint is not connected").
void unmount_stale(const std::string &directory) {
	pid_t pid;
	const char *argv[] = {"fusermount3", "-u", "-z", "-q", directory.c_str(), nullptr};
	if (posix_spawnp(&pid, "fusermount3", nullptr, nullptr, const_cast<char *const *>(argv), environ) == 0) {
		int status;
		waitpid(pid, &status, 0);
	}
}

} // namespace

bool RemoteMount::mount(const std::string &directory, std::string *error) {
	if (impl_->se) {
		*error = "already mounted";
		return false;
	}
	struct stat st;
	if (stat(directory.c_str(), &st) != 0 && errno == ENOTCONN) {
		unmount_stale(directory);
	}
	// mkdir -p
	for (size_t i = 1; i <= directory.size(); i++) {
		if (i == directory.size() || directory[i] == '/') {
			std::string part = directory.substr(0, i);
			if (mkdir(part.c_str(), 0700) != 0 && errno != EEXIST) {
				*error = "can't create " + part + ": " + strerror(errno);
				return false;
			}
		}
	}

	static const struct fuse_lowlevel_ops ops = [] {
		struct fuse_lowlevel_ops o = {};
		o.lookup = Impl::ll_lookup;
		o.forget = Impl::ll_forget;
		o.forget_multi = Impl::ll_forget_multi;
		o.getattr = Impl::ll_getattr;
		o.opendir = Impl::ll_opendir;
		o.readdir = Impl::ll_readdir;
		o.releasedir = Impl::ll_releasedir;
		o.open = Impl::ll_open;
		o.read = Impl::ll_read;
		o.release = Impl::ll_release;
		o.statfs = Impl::ll_statfs;
		return o;
	}();
	struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
	fuse_opt_add_arg(&args, "gdp");
	fuse_opt_add_arg(&args, "-oro,auto_unmount,fsname=ghost,subtype=ghost");
	impl_->se = fuse_session_new(&args, &ops, sizeof(ops), impl_.get());
	fuse_opt_free_args(&args);
	if (!impl_->se) {
		*error = "fuse_session_new failed";
		return false;
	}
	impl_->names = register_mount(directory);
	if (fuse_session_mount(impl_->se, directory.c_str()) != 0) {
		unregister_mount(impl_->names);
		impl_->names.clear();
		fuse_session_destroy(impl_->se);
		impl_->se = nullptr;
		*error = "can't mount on " + directory + " (is /dev/fuse there and fusermount3 installed?)";
		return false;
	}
	directory_ = directory;
	impl_->wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	impl_->stop_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
	impl_->loop = std::thread([impl = impl_.get()] { impl->loop_main(); });
	return true;
}

void RemoteMount::unmount() {
	Impl &i = *impl_;
	if (!i.se) {
		return;
	}
	// FUSE's thread first, so nothing more comes in; then every request it
	// handed over is answered, those that came while it stopped included.
	uint64_t one = 1;
	ssize_t ignored = write(i.stop_fd, &one, sizeof(one));
	(void)ignored;
	i.loop.join();
	i.fail_all();
	fuse_session_unmount(i.se);
	fuse_session_destroy(i.se);
	i.se = nullptr;
	close(i.wake_fd);
	close(i.stop_fd);
	i.wake_fd = i.stop_fd = -1;
	for (auto &[fh, f] : i.files) {
		if (f.range && !f.range_done && on_close_range) {
			on_close_range(f.range);
		}
	}
	i.files.clear();
	i.ranges.clear();
	rmdir(directory_.c_str());
	unregister_mount(i.names);
	i.names.clear();
	directory_.clear();
}

bool RemoteMount::mounted() const {
	return impl_->se != nullptr;
}

bool RemoteMount::contains(const std::string &path) const {
	return !directory_.empty() && path.compare(0, directory_.size(), directory_) == 0 &&
		(path.size() == directory_.size() || path[directory_.size()] == '/');
}

int RemoteMount::notify_fd() const {
	return impl_->wake_fd;
}

void RemoteMount::dispatch() {
	Impl &i = *impl_;
	if (i.wake_fd < 0) {
		return;
	}
	uint64_t count;
	ssize_t ignored = ::read(i.wake_fd, &count, sizeof(count));
	(void)ignored;
	std::deque<Impl::Op> ops;
	{
		std::lock_guard<std::mutex> lock(i.mutex);
		ops.swap(i.ops);
	}
	for (Impl::Op &op : ops) {
		i.handle(op);
	}
}

RemoteMount::Node RemoteMount::add(Node parent, const Entry &entry) {
	Impl &i = *impl_;
	Impl::NodeData *p = i.node(parent);
	if (!p || !p->entry.directory) {
		return 0;
	}
	Node n = i.next_node++;
	Impl::NodeData data;
	data.parent = parent;
	data.entry = entry;
	data.listed_us = monotonic_us();
	i.nodes[n] = std::move(data);
	i.nodes[parent].children.push_back(n);
	return n;
}

void RemoteMount::remove(Node node) {
	Impl &i = *impl_;
	if (node == kRoot) {
		return;
	}
	Impl::NodeData *n = i.node(node);
	if (!n) {
		return;
	}
	if (Impl::NodeData *p = i.node(n->parent)) {
		p->children.erase(std::remove(p->children.begin(), p->children.end(), node), p->children.end());
	}
	std::vector<Node> stack = {node};
	while (!stack.empty()) {
		Node cur = stack.back();
		stack.pop_back();
		Impl::NodeData &d = i.nodes.at(cur);
		stack.insert(stack.end(), d.children.begin(), d.children.end());
		for (Impl::Op &op : d.waiting) {
			fuse_reply_err(op.req, ENOENT);
		}
		for (auto &[fh, f] : i.files) {
			if (f.node == cur && !f.dead) {
				f.dead = true;
				for (const Impl::Read &r : f.pending) {
					fuse_reply_err(r.req, EIO);
				}
				f.pending.clear();
				i.close_range(f);
			}
		}
		i.nodes.erase(cur);
	}
}

void RemoteMount::set_children(Node folder, const std::vector<Entry> &children) {
	Impl &i = *impl_;
	Impl::NodeData *f = i.node(folder);
	if (!f) {
		return;
	}
	// Matched by name: what is still there keeps its node (and the kernel's
	// idea of it), what is gone goes.
	std::unordered_map<std::string, Node> had;
	for (Node c : f->children) {
		had[i.nodes.at(c).entry.name] = c;
	}
	std::vector<Node> now;
	for (const Entry &e : children) {
		auto it = had.find(e.name);
		if (it != had.end() && i.nodes.at(it->second).entry.directory == e.directory) {
			Impl::NodeData &d = i.nodes.at(it->second);
			bool listed = d.entry.listed;
			d.entry = e;
			d.entry.listed = listed && e.listed; // known contents stay known
			now.push_back(it->second);
			had.erase(it);
		} else {
			Node n = i.next_node++;
			Impl::NodeData data;
			data.parent = folder;
			data.entry = e;
			data.listed_us = monotonic_us();
			i.nodes[n] = std::move(data);
			now.push_back(n);
		}
	}
	f = i.node(folder);
	f->children.clear();
	for (auto &[name, gone] : had) {
		remove(gone);
	}
	f = i.node(folder);
	f->children = std::move(now);
	f->entry.listed = true;
	f->listing = false;
	f->listed_us = monotonic_us();
	std::vector<Impl::Op> waiting = std::move(f->waiting);
	f->waiting.clear();
	for (Impl::Op &op : waiting) {
		i.handle(op);
	}
}

void RemoteMount::fail_children(Node folder, int error) {
	Impl &i = *impl_;
	Impl::NodeData *f = i.node(folder);
	if (!f) {
		return;
	}
	f->listing = false;
	std::vector<Impl::Op> waiting = std::move(f->waiting);
	f->waiting.clear();
	for (Impl::Op &op : waiting) {
		fuse_reply_err(op.req, error);
	}
}

std::string RemoteMount::path_of(Node node) const {
	const Impl &i = *impl_;
	std::vector<const std::string *> parts;
	for (Node n = node; n != kRoot;) {
		auto it = i.nodes.find(n);
		if (it == i.nodes.end()) {
			return "";
		}
		parts.push_back(&it->second.entry.name);
		n = it->second.parent;
	}
	std::string path = directory_;
	for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
		path += "/" + **it;
	}
	return path;
}

RemoteMount::Node RemoteMount::child(Node parent, const std::string &name) const {
	const Impl &i = *impl_;
	auto it = i.nodes.find(parent);
	if (it == i.nodes.end()) {
		return 0;
	}
	for (Node c : it->second.children) {
		if (i.nodes.at(c).entry.name == name) {
			return c;
		}
	}
	return 0;
}

void RemoteMount::range_data(uint64_t range, const uint8_t *data, size_t len) {
	Impl &i = *impl_;
	auto r = i.ranges.find(range);
	if (r == i.ranges.end()) {
		return;
	}
	Impl::OpenFile &f = i.files.at(r->second);
	f.buf.insert(f.buf.end(), data, data + len);
	i.serve(f);
}

void RemoteMount::range_end(uint64_t range, int error) {
	Impl &i = *impl_;
	auto r = i.ranges.find(range);
	if (r == i.ranges.end()) {
		return;
	}
	Impl::OpenFile &f = i.files.at(r->second);
	f.range_done = true;
	f.error = error;
	i.ranges.erase(r);
	i.serve(f);
}

uint64_t RemoteMount::ranges_opened() const {
	return impl_->ranges_opened;
}

bool inside_own_mount(const std::string &path) {
	std::lock_guard<std::mutex> lock(g_mounts_mutex);
	for (const std::string &dir : g_mounts) {
		if (under_path(path, dir)) {
			return true;
		}
	}
	return false;
}

} // namespace gdp

#else // !GDP_HAVE_FUSE

namespace gdp {

struct RemoteMount::Impl {};

RemoteMount::RemoteMount() = default;
RemoteMount::~RemoteMount() = default;
bool RemoteMount::supported() {
	return false;
}
bool RemoteMount::mount(const std::string &, std::string *error) {
	*error = "this build has no FUSE";
	return false;
}
void RemoteMount::unmount() {}
bool RemoteMount::mounted() const {
	return false;
}
bool RemoteMount::contains(const std::string &) const {
	return false;
}
int RemoteMount::notify_fd() const {
	return -1;
}
void RemoteMount::dispatch() {}
RemoteMount::Node RemoteMount::add(Node, const Entry &) {
	return 0;
}
void RemoteMount::remove(Node) {}
void RemoteMount::set_children(Node, const std::vector<Entry> &) {}
void RemoteMount::fail_children(Node, int) {}
std::string RemoteMount::path_of(Node) const {
	return "";
}
RemoteMount::Node RemoteMount::child(Node, const std::string &) const {
	return 0;
}
void RemoteMount::range_data(uint64_t, const uint8_t *, size_t) {}
void RemoteMount::range_end(uint64_t, int) {}
uint64_t RemoteMount::ranges_opened() const {
	return 0;
}
bool inside_own_mount(const std::string &) {
	return false;
}

} // namespace gdp

#endif
