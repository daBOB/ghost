// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/my_folders.hpp"

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <system_error>
#endif

namespace spectre {

#ifdef _WIN32

std::vector<MyFolder> my_folders() {
	std::vector<MyFolder> out;
	// No "insert a disk" dialog for an empty drive.
	DWORD old_mode = 0;
	SetThreadErrorMode(SEM_FAILCRITICALERRORS, &old_mode);
	DWORD drives = GetLogicalDrives();
	for (int i = 0; i < 26; i++) {
		if (!(drives & (1u << i))) {
			continue;
		}
		wchar_t root[] = {static_cast<wchar_t>(L'A' + i), L':', L'\\', 0};
		UINT type = GetDriveTypeW(root);
		if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE && type != DRIVE_CDROM) {
			continue; // network drives are someone else's to share
		}
		DWORD attributes = GetFileAttributesW(root); // fails for an empty card reader or drive
		if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY)) {
			continue;
		}
		char letter = static_cast<char>('A' + i);
		out.push_back({std::string(1, letter) + ":\\", std::string("Drive ") + letter});
	}
	SetThreadErrorMode(old_mode, nullptr);
	return out;
}

#else

namespace {

namespace fs = std::filesystem;

std::string user_name() {
	struct passwd *pw = getpwuid(getuid());
	if (pw && pw->pw_name) {
		return pw->pw_name;
	}
	const char *user = getenv("USER");
	return user ? user : "";
}

std::string home_folder() {
	const char *home = getenv("HOME");
	if (home && *home) {
		return home;
	}
	struct passwd *pw = getpwuid(getuid());
	return pw && pw->pw_dir ? pw->pw_dir : "";
}

// The folders in `base` something is mounted on (an empty mount point left
// behind is skipped), by name. Links are skipped: macOS's /Volumes has one
// to "/" for the startup disk.
void add_mounted(const std::string &base, std::vector<MyFolder> *out) {
	struct stat base_st;
	if (lstat(base.c_str(), &base_st) != 0 || !S_ISDIR(base_st.st_mode)) {
		return;
	}
	std::vector<MyFolder> found;
	std::error_code ec;
	for (fs::directory_iterator it(base, fs::directory_options::skip_permission_denied, ec), end;
		 !ec && it != end; it.increment(ec)) {
		struct stat st;
		std::string path = it->path().string();
		if (lstat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_dev != base_st.st_dev) {
			found.push_back({path, it->path().filename().string()});
		}
	}
	std::sort(found.begin(), found.end(), [](const MyFolder &a, const MyFolder &b) { return a.name < b.name; });
	out->insert(out->end(), found.begin(), found.end());
}

} // namespace

std::vector<MyFolder> my_folders() {
	std::vector<MyFolder> out;
	std::string home = home_folder();
	if (!home.empty()) {
		out.push_back({home, "Home"});
	}
#ifdef __APPLE__
	add_mounted("/Volumes", &out);
#else
	std::string user = user_name();
	if (!user.empty()) {
		add_mounted("/run/media/" + user, &out);
		add_mounted("/media/" + user, &out);
	}
#endif
	return out;
}

#endif

} // namespace spectre
