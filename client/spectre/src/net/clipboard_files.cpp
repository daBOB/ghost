// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/clipboard_files.hpp"

#ifdef _WIN32
#include <windows.h>

#include <shellapi.h>
#else
#include "gdp/file_transfer.hpp"

#include <SDL3/SDL.h>
#endif

namespace spectre {

#ifdef _WIN32

std::vector<std::string> local_copied_files(bool *holds_files) {
	std::vector<std::string> paths;
	*holds_files = IsClipboardFormatAvailable(CF_HDROP) != 0;
	if (!*holds_files || !OpenClipboard(nullptr)) {
		return paths;
	}
	if (HDROP drop = static_cast<HDROP>(GetClipboardData(CF_HDROP))) {
		UINT count = DragQueryFileW(drop, 0xFFFFFFFF, nullptr, 0);
		for (UINT i = 0; i < count; i++) {
			UINT len = DragQueryFileW(drop, i, nullptr, 0);
			std::wstring wide(len + 1, L'\0');
			DragQueryFileW(drop, i, wide.data(), len + 1);
			wide.resize(len);
			int bytes = WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), nullptr, 0, nullptr, nullptr);
			std::string utf8(bytes, '\0');
			WideCharToMultiByte(CP_UTF8, 0, wide.data(), (int)wide.size(), utf8.data(), bytes, nullptr, nullptr);
			if (!utf8.empty()) {
				paths.push_back(std::move(utf8));
			}
		}
	}
	CloseClipboard();
	return paths;
}

#else

std::vector<std::string> local_copied_files(bool *holds_files) {
	size_t count = 0;
	char **mimes = SDL_GetClipboardMimeTypes(&count);
	std::vector<std::string> offered;
	for (size_t i = 0; mimes && i < count; i++) {
		offered.emplace_back(mimes[i]);
	}
	SDL_free(mimes);
	std::string mime = gdp::select_copied_files_mime(offered);
	*holds_files = !mime.empty();
	if (mime.empty()) {
		return {};
	}
	size_t size = 0;
	void *data = SDL_GetClipboardData(mime.c_str(), &size);
	std::string raw = data ? std::string(static_cast<const char *>(data), size) : std::string();
	SDL_free(data);
	return gdp::copied_file_paths(mime, raw);
}

#endif

} // namespace spectre
