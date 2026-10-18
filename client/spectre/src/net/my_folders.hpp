// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// What "share my files" (spectre -F) shares with the host, as RDP's drive
// redirection does: the home folder, then on Windows every local drive
// (fixed, removable or optical with a disc in it); elsewhere the removable
// drives mounted for this user (/run/media/$USER, /media/$USER, and
// /Volumes on macOS). Never the whole filesystem: that is the user's keys
// and every other user's files, and full of links and devices a share
// leaves out anyway. Looked at again while connected, so a drive plugged
// in later is shared too.
#pragma once

#include <string>
#include <vector>

namespace spectre {

struct MyFolder {
	std::string path; // UTF-8
	std::string name; // what the host is told to call it
};

std::vector<MyFolder> my_folders();

} // namespace spectre
