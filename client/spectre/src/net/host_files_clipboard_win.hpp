// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// HostFilesClipboard (Windows): the host's copied files (gdp-spec.md
// §7.12) on the Windows clipboard as Explorer's virtual files, read from
// the host only when pasted. Windows has no FUSE to mount them in, so
// instead of paths the clipboard holds an IDataObject offering
//
// - CFSTR_FILEDESCRIPTORW: every file and folder by its path from the
//   paste target (HostFileTree), the folders the host left unlisted asked
//   for first;
// - CFSTR_FILECONTENTS: an IStream per file, whose reads come from the
//   host (HostFileReads) as Explorer makes them;
// - CFSTR_PREFERREDDROPEFFECT: always a copy, never a cut;
// - "Ghost.HostFiles", so spectre knows the clipboard holds its own offer
//   (on_clipboard()), and "ExcludeClipboardContentFromMonitorProcessing",
//   which keeps it out of Win+V's history and the cloud clipboard;
//
// and IDataObjectAsyncCapability, so Explorer copies on a thread of its
// own, with its progress dialog, rather than on its UI's.
//
// Explorer's calls come in over COM to the thread that owns the object's
// apartment: a thread of this object's own (an STA, OleInitialize), which
// blocks in a read until the host's bytes come. It never touches the
// connection; the main thread does that, through HostFileReads.
#pragma once

#include "net/host_file_reads.hpp"
#include "session.pb.h"

#include <memory>

namespace spectre {

class HostFilesClipboard {
public:
	explicit HostFilesClipboard(std::shared_ptr<HostFileReads> reads);
	// Withdraws the offer and ends the thread. HostFileReads::close() first,
	// so a read the thread is blocked in returns.
	~HostFilesClipboard();
	HostFilesClipboard(const HostFilesClipboard &) = delete;
	HostFilesClipboard &operator=(const HostFilesClipboard &) = delete;

	// Main thread. Puts the host's list on the clipboard, in place of what
	// is there. `tree`: file-clipboard is in effect (HostFileTree).
	void offer(const gdp::session::FileList &list, bool tree);
	// Takes the offer off the clipboard if it is still there (never
	// OleFlushClipboard: that would fetch every file).
	void withdraw();

	// Whether the clipboard holds a spectre's offer: a clipboard update
	// that is our own, not a local copy.
	static bool on_clipboard();

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace spectre
