// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Sidebar entries for the folders a client shares (gdp-spec.md §7.12,
// file-share): a GTK bookmark (Nautilus and GTK file choosers read
// ~/.config/gtk-3.0/bookmarks) and a KDE Places entry (Dolphin, KDE file
// dialogs: ~/.local/share/user-places.xbel, touched only if it exists).
// Added when a share is mounted, removed when it goes; whatever a wraith
// that died left behind goes at the next start (remove by prefix).
#pragma once

#include <string>

namespace wraith {

// Adds an entry labelled `label` for the folder at `path`, if there is none.
void add_file_bookmark(const std::string &path, const std::string &label);

// Removes every entry for `prefix` or a path inside it.
void remove_file_bookmarks(const std::string &prefix);

// The files these live in, for tests: under $XDG_CONFIG_HOME and
// $XDG_DATA_HOME (or ~/.config, ~/.local/share).
std::string gtk_bookmarks_path();
std::string kde_places_path();

} // namespace wraith
