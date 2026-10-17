// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "session/file_bookmarks.hpp"

#include "gdp/file_transfer.hpp"
#include "util/log.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <vector>

#include <pwd.h>
#include <unistd.h>

namespace wraith {

namespace {

std::string home() {
	const char *h = getenv("HOME");
	if (h && *h) {
		return h;
	}
	const struct passwd *pw = getpwuid(getuid());
	return pw && pw->pw_dir ? pw->pw_dir : "";
}

std::string xdg_dir(const char *variable, const char *fallback) {
	const char *v = getenv(variable);
	return v && *v ? std::string(v) : home() + fallback;
}

bool read_file(const std::string &path, std::string *out) {
	std::ifstream in(path, std::ios::binary);
	if (!in) {
		return false;
	}
	std::ostringstream s;
	s << in.rdbuf();
	*out = s.str();
	return true;
}

// Written beside it and renamed over it, so a reader never sees half a file.
void write_file(const std::string &path, const std::string &content) {
	std::error_code ec;
	std::filesystem::create_directories(std::filesystem::path(path).parent_path(), ec);
	std::string tmp = path + ".ghost-" + std::to_string(getpid());
	{
		std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
		out << content;
		if (!out) {
			WLOG_ERROR("files: can't write %s", tmp.c_str());
			std::remove(tmp.c_str());
			return;
		}
	}
	if (std::rename(tmp.c_str(), path.c_str()) != 0) {
		WLOG_ERROR("files: can't replace %s", path.c_str());
		std::remove(tmp.c_str());
	}
}

// Whether `uri` is `prefix`'s or inside it.
bool under(const std::string &uri, const std::string &prefix_uri) {
	return uri.compare(0, prefix_uri.size(), prefix_uri) == 0 &&
		(uri.size() == prefix_uri.size() || uri[prefix_uri.size()] == '/');
}

std::string xml_escape(const std::string &s) {
	std::string out;
	for (char c : s) {
		switch (c) {
		case '&': out += "&amp;"; break;
		case '<': out += "&lt;"; break;
		case '>': out += "&gt;"; break;
		case '"': out += "&quot;"; break;
		default: out += c;
		}
	}
	return out;
}

// The <bookmark> elements of an XBEL file whose href is under `prefix_uri`,
// as [begin, end) offsets.
std::vector<std::pair<size_t, size_t>> xbel_entries_under(const std::string &xml, const std::string &prefix_uri) {
	std::vector<std::pair<size_t, size_t>> found;
	const std::string open = "<bookmark href=\"";
	for (size_t at = xml.find(open); at != std::string::npos; at = xml.find(open, at + 1)) {
		size_t href = at + open.size();
		size_t quote = xml.find('"', href);
		size_t close = xml.find("</bookmark>", at);
		if (quote == std::string::npos || close == std::string::npos) {
			break;
		}
		if (under(xml.substr(href, quote - href), prefix_uri)) {
			size_t end = close + std::string("</bookmark>").size();
			if (end < xml.size() && xml[end] == '\n') {
				end++;
			}
			// The element's own indentation goes with it.
			size_t begin = at;
			while (begin > 0 && (xml[begin - 1] == ' ' || xml[begin - 1] == '\t')) {
				begin--;
			}
			found.emplace_back(begin, end);
		}
	}
	return found;
}

} // namespace

std::string gtk_bookmarks_path() {
	return xdg_dir("XDG_CONFIG_HOME", "/.config") + "/gtk-3.0/bookmarks";
}

std::string kde_places_path() {
	return xdg_dir("XDG_DATA_HOME", "/.local/share") + "/user-places.xbel";
}

void add_file_bookmark(const std::string &path, const std::string &label) {
	const std::string uri = gdp::file_uri(path);

	std::string gtk;
	read_file(gtk_bookmarks_path(), &gtk);
	bool listed = false;
	std::istringstream lines(gtk);
	for (std::string line; std::getline(lines, line);) {
		listed = listed || line.substr(0, line.find(' ')) == uri;
	}
	if (!listed) {
		if (!gtk.empty() && gtk.back() != '\n') {
			gtk += '\n';
		}
		write_file(gtk_bookmarks_path(), gtk + uri + " " + label + "\n");
	}

	std::string xml;
	if (read_file(kde_places_path(), &xml) && xbel_entries_under(xml, uri).empty()) {
		size_t end = xml.rfind("</xbel>");
		if (end != std::string::npos) {
			xml.insert(end, " <bookmark href=\"" + xml_escape(uri) + "\">\n  <title>" + xml_escape(label) +
					"</title>\n </bookmark>\n");
			write_file(kde_places_path(), xml);
		}
	}
}

void remove_file_bookmarks(const std::string &prefix) {
	const std::string prefix_uri = gdp::file_uri(prefix);

	std::string gtk;
	if (read_file(gtk_bookmarks_path(), &gtk)) {
		std::string kept;
		bool removed = false;
		std::istringstream lines(gtk);
		for (std::string line; std::getline(lines, line);) {
			if (under(line.substr(0, line.find(' ')), prefix_uri)) {
				removed = true;
			} else {
				kept += line + "\n";
			}
		}
		if (removed) {
			write_file(gtk_bookmarks_path(), kept);
		}
	}

	std::string xml;
	if (read_file(kde_places_path(), &xml)) {
		auto entries = xbel_entries_under(xml, prefix_uri);
		for (auto it = entries.rbegin(); it != entries.rend(); ++it) {
			xml.erase(it->first, it->second - it->first);
		}
		if (!entries.empty()) {
			write_file(kde_places_path(), xml);
		}
	}
}

} // namespace wraith
