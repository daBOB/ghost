// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The files a local copy put on the clipboard (a file manager's Copy), for
// file-clipboard (gdp-spec.md §7.12). Linux and macOS read them through
// SDL's mime types (x-special/gnome-copied-files, text/uri-list); Windows
// from Explorer's CF_HDROP, which SDL doesn't read. Main thread, with SDL's
// video subsystem up.
#pragma once

#include <string>
#include <vector>

namespace spectre {

// The local paths (UTF-8) of the files on the clipboard, in order; sets
// `holds_files` when it holds a copy of files at all, which then never also
// goes to the host as text, even if none of them is local.
std::vector<std::string> local_copied_files(bool *holds_files);

} // namespace spectre
