// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

#include "net/host_files_clipboard_win.hpp"

#include "gdp/file_transfer.hpp"
#include "log.hpp"
#include "net/host_file_tree.hpp"

#include <windows.h>
#include <ole2.h>
#include <shlobj.h>
#include <shobjidl.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace spectre {

namespace {

// Listing the folders a list left unlisted, at paste time: past this,
// nothing is pasted rather than half a tree.
constexpr auto kFillTimeout = std::chrono::seconds(60);
// How long one read waits on the host. HostFileReads::tick() fails a
// request the host has gone quiet on well before; this is the backstop.
constexpr uint32_t kReadTimeoutMs = 2 * gdp::kFileReplyTimeoutMs;
// OleSetClipboard while another program has the clipboard open
// (CLIPBRD_E_CANT_OPEN; SDL's own reads, a clipboard manager): tries.
constexpr int kClipboardTries = 10;

constexpr UINT kOfferMessage = WM_APP + 1;
constexpr UINT kWithdrawMessage = WM_APP + 2;
constexpr UINT kQuitMessage = WM_APP + 3;

struct Formats {
	CLIPFORMAT descriptor = static_cast<CLIPFORMAT>(RegisterClipboardFormatW(L"FileGroupDescriptorW"));
	CLIPFORMAT contents = static_cast<CLIPFORMAT>(RegisterClipboardFormatW(L"FileContents"));
	CLIPFORMAT drop_effect = static_cast<CLIPFORMAT>(RegisterClipboardFormatW(L"Preferred DropEffect"));
	CLIPFORMAT ours = static_cast<CLIPFORMAT>(RegisterClipboardFormatW(L"Ghost.HostFiles"));
	CLIPFORMAT no_history =
		static_cast<CLIPFORMAT>(RegisterClipboardFormatW(L"ExcludeClipboardContentFromMonitorProcessing"));
};

const Formats &formats() {
	static const Formats f;
	return f;
}

FORMATETC format_of(CLIPFORMAT cf, DWORD tymed) {
	return FORMATETC{cf, nullptr, DVASPECT_CONTENT, -1, tymed};
}

std::wstring wide(const std::string &utf8) {
	if (utf8.empty()) {
		return {};
	}
	int n = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
	std::wstring out(static_cast<size_t>(n), L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), out.data(), n);
	return out;
}

// Unix milliseconds as a FILETIME (100 ns units since 1601).
FILETIME filetime(int64_t unix_ms) {
	uint64_t t = static_cast<uint64_t>(unix_ms) * 10000 + 116444736000000000ull;
	return FILETIME{static_cast<DWORD>(t), static_cast<DWORD>(t >> 32)};
}

HRESULT hglobal_medium(const void *data, size_t size, STGMEDIUM *medium) {
	HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, size);
	if (!h) {
		return E_OUTOFMEMORY;
	}
	std::memcpy(GlobalLock(h), data, size);
	GlobalUnlock(h);
	medium->tymed = TYMED_HGLOBAL;
	medium->hGlobal = h;
	medium->pUnkForRelease = nullptr;
	return S_OK;
}

// One file's bytes, read from the host as Explorer asks: in order from
// where it last read, a new request from wherever it seeks to.
class FileStream : public IStream {
public:
	FileStream(std::shared_ptr<HostFileReads> reads, HostFileReads::Target target, const HostFileTree::File &file)
		: reads_(std::move(reads)), target_(target), size_(file.size), modified_unix_ms_(file.modified_unix_ms),
		  name_(wide(file.name)), path_(file.path) {}

	// IUnknown
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **out) override {
		if (!out) {
			return E_POINTER;
		}
		if (riid == IID_IUnknown || riid == IID_ISequentialStream || riid == IID_IStream) {
			*out = static_cast<IStream *>(this);
			AddRef();
			return S_OK;
		}
		*out = nullptr;
		return E_NOINTERFACE;
	}
	ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
	ULONG STDMETHODCALLTYPE Release() override {
		LONG n = InterlockedDecrement(&refs_);
		if (n == 0) {
			delete this; // the request, if any, is cancelled with it
		}
		return static_cast<ULONG>(n);
	}

	// ISequentialStream
	HRESULT STDMETHODCALLTYPE Read(void *pv, ULONG cb, ULONG *pcb_read) override {
		if (!pv) {
			return STG_E_INVALIDPOINTER;
		}
		ULONG got = 0;
		// A short read means the end to many callers: fill it all, unless
		// the file ends or fails first.
		while (got < cb && !failed_ && !ended_) {
			if (!read_) {
				read_ = reads_->post(target_, pos_);
			}
			int64_t n = read_->read(static_cast<uint8_t *>(pv) + got, cb - got, kReadTimeoutMs);
			if (n > 0) {
				got += static_cast<ULONG>(n);
				pos_ += static_cast<uint64_t>(n);
			} else if (n == 0) {
				ended_ = true;
				read_.reset();
				if (pos_ < size_) {
					// Shorter than listed: it changed on the host. What came
					// is passed on, then an error, as the mount does.
					SLOG_ERROR("files: %s: the host sent %llu of its %llu bytes", path_.c_str(),
						(unsigned long long)pos_, (unsigned long long)size_);
					failed_ = true;
				}
			} else {
				SLOG_ERROR("files: %s: reading it from the host failed at byte %llu", path_.c_str(),
					(unsigned long long)pos_);
				failed_ = true;
				read_.reset();
			}
		}
		if (pcb_read) {
			*pcb_read = got;
		}
		return got == 0 && failed_ ? STG_E_READFAULT : S_OK;
	}
	HRESULT STDMETHODCALLTYPE Write(const void *, ULONG, ULONG *) override { return STG_E_ACCESSDENIED; }

	// IStream
	HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER move, DWORD origin, ULARGE_INTEGER *new_position) override {
		int64_t base = 0;
		switch (origin) {
		case STREAM_SEEK_SET: base = 0; break;
		case STREAM_SEEK_CUR: base = static_cast<int64_t>(pos_); break;
		case STREAM_SEEK_END: base = static_cast<int64_t>(size_); break;
		default: return STG_E_INVALIDFUNCTION;
		}
		int64_t to = base + move.QuadPart;
		if (to < 0) {
			return STG_E_INVALIDFUNCTION;
		}
		if (static_cast<uint64_t>(to) != pos_) {
			pos_ = static_cast<uint64_t>(to);
			read_.reset(); // cancelled; the next read asks from here
			ended_ = false;
			failed_ = false;
		}
		if (new_position) {
			new_position->QuadPart = pos_;
		}
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER) override { return STG_E_ACCESSDENIED; }
	HRESULT STDMETHODCALLTYPE CopyTo(IStream *to, ULARGE_INTEGER cb, ULARGE_INTEGER *read,
		ULARGE_INTEGER *written) override {
		if (!to) {
			return STG_E_INVALIDPOINTER;
		}
		std::vector<uint8_t> buf(256 * 1024);
		uint64_t left = cb.QuadPart, total_read = 0, total_written = 0;
		HRESULT hr = S_OK;
		while (left > 0) {
			ULONG want = static_cast<ULONG>(std::min<uint64_t>(left, buf.size()));
			ULONG got = 0;
			hr = Read(buf.data(), want, &got);
			if (FAILED(hr) || got == 0) {
				break;
			}
			total_read += got;
			ULONG put = 0;
			hr = to->Write(buf.data(), got, &put);
			total_written += put;
			if (FAILED(hr)) {
				break;
			}
			left -= got;
		}
		if (read) {
			read->QuadPart = total_read;
		}
		if (written) {
			written->QuadPart = total_written;
		}
		return FAILED(hr) ? hr : S_OK;
	}
	HRESULT STDMETHODCALLTYPE Commit(DWORD) override { return S_OK; }
	HRESULT STDMETHODCALLTYPE Revert() override { return S_OK; }
	HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override {
		return STG_E_INVALIDFUNCTION;
	}
	HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override {
		return STG_E_INVALIDFUNCTION;
	}
	HRESULT STDMETHODCALLTYPE Stat(STATSTG *stat, DWORD flag) override {
		if (!stat) {
			return STG_E_INVALIDPOINTER;
		}
		std::memset(stat, 0, sizeof *stat);
		stat->type = STGTY_STREAM;
		stat->cbSize.QuadPart = size_;
		stat->grfMode = STGM_READ;
		if (modified_unix_ms_ > 0) {
			stat->mtime = filetime(modified_unix_ms_);
		}
		if (!(flag & STATFLAG_NONAME)) {
			size_t bytes = (name_.size() + 1) * sizeof(wchar_t);
			stat->pwcsName = static_cast<LPOLESTR>(CoTaskMemAlloc(bytes));
			if (!stat->pwcsName) {
				return STG_E_INSUFFICIENTMEMORY;
			}
			std::memcpy(stat->pwcsName, name_.c_str(), bytes);
		}
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE Clone(IStream **) override { return E_NOTIMPL; }

private:
	~FileStream() = default;

	LONG refs_ = 1;
	std::shared_ptr<HostFileReads> reads_;
	HostFileReads::Target target_;
	uint64_t size_;
	int64_t modified_unix_ms_;
	std::wstring name_;
	std::string path_; // for logs
	uint64_t pos_ = 0;
	std::unique_ptr<HostFileReads::Read> read_;
	bool ended_ = false;
	bool failed_ = false;
};

// One of the host's lists, as the clipboard holds it.
class DataObject : public IDataObject, public IDataObjectAsyncCapability {
public:
	DataObject(std::shared_ptr<HostFileReads> reads, gdp::session::FileList list, bool tree)
		: reads_(std::move(reads)), list_(std::move(list)), tree_(tree) {}

	// IUnknown
	HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **out) override {
		if (!out) {
			return E_POINTER;
		}
		if (riid == IID_IUnknown || riid == IID_IDataObject) {
			*out = static_cast<IDataObject *>(this);
		} else if (riid == __uuidof(IDataObjectAsyncCapability)) {
			*out = static_cast<IDataObjectAsyncCapability *>(this);
		} else {
			*out = nullptr;
			return E_NOINTERFACE;
		}
		AddRef();
		return S_OK;
	}
	ULONG STDMETHODCALLTYPE AddRef() override { return static_cast<ULONG>(InterlockedIncrement(&refs_)); }
	ULONG STDMETHODCALLTYPE Release() override {
		LONG n = InterlockedDecrement(&refs_);
		if (n == 0) {
			delete this;
		}
		return static_cast<ULONG>(n);
	}

	// IDataObject
	HRESULT STDMETHODCALLTYPE GetData(FORMATETC *in, STGMEDIUM *medium) override {
		if (!in || !medium) {
			return E_INVALIDARG;
		}
		std::memset(medium, 0, sizeof *medium);
		HRESULT hr = check(in);
		if (FAILED(hr)) {
			return hr;
		}
		const Formats &f = formats();
		if (in->cfFormat == f.descriptor) {
			return descriptors(medium);
		}
		if (in->cfFormat == f.contents) {
			return contents(in->lindex, medium);
		}
		if (in->cfFormat == f.drop_effect) {
			DWORD effect = DROPEFFECT_COPY; // never a cut: nothing deletes an original across
			return hglobal_medium(&effect, sizeof effect, medium);
		}
		if (in->cfFormat == f.ours) {
			uint64_t id = list_.list_id();
			return hglobal_medium(&id, sizeof id, medium);
		}
		if (in->cfFormat == f.no_history) {
			DWORD zero = 0;
			return hglobal_medium(&zero, sizeof zero, medium);
		}
		for (const Stored &s : stored_) {
			if (s.format.cfFormat == in->cfFormat) {
				medium->tymed = TYMED_HGLOBAL;
				medium->hGlobal = OleDuplicateData(s.medium.hGlobal, in->cfFormat, 0);
				return medium->hGlobal ? S_OK : E_OUTOFMEMORY;
			}
		}
		return DV_E_FORMATETC;
	}
	HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC *, STGMEDIUM *) override { return DATA_E_FORMATETC; }
	HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC *in) override { return in ? check(in) : E_INVALIDARG; }
	HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC *, FORMATETC *out) override {
		if (out) {
			out->ptd = nullptr;
		}
		return DATA_S_SAMEFORMATETC;
	}
	// What Explorer tells the source (Performed DropEffect, Paste
	// Succeeded, its drag images' formats): kept, and given back.
	HRESULT STDMETHODCALLTYPE SetData(FORMATETC *format, STGMEDIUM *medium, BOOL release) override {
		if (!format || !medium) {
			return E_INVALIDARG;
		}
		if (medium->tymed != TYMED_HGLOBAL || !(format->tymed & TYMED_HGLOBAL)) {
			return E_NOTIMPL;
		}
		Stored s;
		s.format = *format;
		s.format.ptd = nullptr;
		s.format.tymed = TYMED_HGLOBAL;
		if (release) {
			s.medium = *medium;
		} else {
			s.medium = {};
			s.medium.tymed = TYMED_HGLOBAL;
			s.medium.hGlobal = OleDuplicateData(medium->hGlobal, format->cfFormat, 0);
			if (!s.medium.hGlobal) {
				return E_OUTOFMEMORY;
			}
		}
		for (auto it = stored_.begin(); it != stored_.end(); ++it) {
			if (it->format.cfFormat == format->cfFormat) {
				ReleaseStgMedium(&it->medium);
				stored_.erase(it);
				break;
			}
		}
		stored_.push_back(s);
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD direction, IEnumFORMATETC **out) override {
		if (!out) {
			return E_INVALIDARG;
		}
		if (direction != DATADIR_GET) {
			*out = nullptr;
			return E_NOTIMPL;
		}
		const Formats &f = formats();
		std::vector<FORMATETC> all = {
			format_of(f.descriptor, TYMED_HGLOBAL),
			format_of(f.contents, TYMED_ISTREAM),
			format_of(f.drop_effect, TYMED_HGLOBAL),
			format_of(f.ours, TYMED_HGLOBAL),
			format_of(f.no_history, TYMED_HGLOBAL),
		};
		for (const Stored &s : stored_) {
			all.push_back(s.format);
		}
		return SHCreateStdEnumFmtEtc(static_cast<UINT>(all.size()), all.data(), out);
	}
	HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC *, DWORD, IAdviseSink *, DWORD *) override {
		return OLE_E_ADVISENOTSUPPORTED;
	}
	HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override { return OLE_E_ADVISENOTSUPPORTED; }
	HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA **) override { return OLE_E_ADVISENOTSUPPORTED; }

	// IDataObjectAsyncCapability: Explorer copies on a thread of its own.
	HRESULT STDMETHODCALLTYPE SetAsyncMode(BOOL async) override {
		async_ = async;
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE GetAsyncMode(BOOL *async) override {
		if (!async) {
			return E_INVALIDARG;
		}
		*async = async_;
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE StartOperation(IBindCtx *) override {
		in_operation_ = TRUE;
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE InOperation(BOOL *in) override {
		if (!in) {
			return E_INVALIDARG;
		}
		*in = in_operation_;
		return S_OK;
	}
	HRESULT STDMETHODCALLTYPE EndOperation(HRESULT, IBindCtx *, DWORD) override {
		in_operation_ = FALSE;
		return S_OK;
	}

private:
	struct Stored {
		FORMATETC format;
		STGMEDIUM medium;
	};

	~DataObject() {
		for (Stored &s : stored_) {
			ReleaseStgMedium(&s.medium);
		}
	}

	HRESULT check(const FORMATETC *in) const {
		if (in->dwAspect != DVASPECT_CONTENT) {
			return DV_E_DVASPECT;
		}
		const Formats &f = formats();
		if (in->cfFormat == f.contents) {
			return in->tymed & TYMED_ISTREAM ? S_OK : DV_E_TYMED;
		}
		if (in->cfFormat == f.descriptor || in->cfFormat == f.drop_effect || in->cfFormat == f.ours ||
			in->cfFormat == f.no_history) {
			return in->tymed & TYMED_HGLOBAL ? S_OK : DV_E_TYMED;
		}
		for (const Stored &s : stored_) {
			if (s.format.cfFormat == in->cfFormat) {
				return in->tymed & TYMED_HGLOBAL ? S_OK : DV_E_TYMED;
			}
		}
		return DV_E_FORMATETC;
	}

	// The whole tree, its unlisted folders asked for first: once, when the
	// paste first wants it. This thread waits on the host meanwhile.
	bool ensure_files() {
		if (files_) {
			return true;
		}
		HostFileTree tree(list_, tree_);
		std::string why;
		HostFileTree::ListFolder list_folder = [&](uint32_t index, uint32_t timeout_ms,
												   std::vector<gdp::session::FileListing> *frames) {
			return reads_->post_listing({tree.list_id(), index})->listing(frames, timeout_ms);
		};
		if (!tree.fill(list_folder, std::chrono::steady_clock::now() + kFillTimeout, &why)) {
			SLOG_ERROR("files: can't paste the host's copied files: %s", why.c_str());
			return false;
		}
		std::vector<std::string> dropped;
		std::vector<HostFileTree::File> files = tree.files(&dropped);
		constexpr size_t kLogged = 20;
		for (size_t i = 0; i < dropped.size() && i < kLogged; i++) {
			SLOG_INFO("files: left out of the paste: %s", dropped[i].c_str());
		}
		if (dropped.size() > kLogged) {
			SLOG_INFO("files: and %zu more left out", dropped.size() - kLogged);
		}
		if (files.empty()) {
			SLOG_ERROR("files: nothing the host copied can be pasted here");
			return false;
		}
		SLOG_INFO("files: pasting %zu of the host's file(s) and folder(s)", files.size());
		files_ = std::move(files);
		return true;
	}

	HRESULT descriptors(STGMEDIUM *medium) {
		if (!ensure_files()) {
			return E_FAIL;
		}
		size_t n = files_->size();
		size_t bytes = offsetof(FILEGROUPDESCRIPTORW, fgd) + n * sizeof(FILEDESCRIPTORW);
		HGLOBAL h = GlobalAlloc(GHND, bytes);
		if (!h) {
			return E_OUTOFMEMORY;
		}
		auto *group = static_cast<FILEGROUPDESCRIPTORW *>(GlobalLock(h));
		group->cItems = static_cast<UINT>(n);
		FILEDESCRIPTORW *d = group->fgd;
		for (size_t i = 0; i < n; i++) {
			const HostFileTree::File &file = (*files_)[i];
			d[i].dwFlags = static_cast<DWORD>(FD_ATTRIBUTES | FD_PROGRESSUI | FD_UNICODE);
			d[i].dwFileAttributes = file.directory ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL;
			if (!file.directory) {
				d[i].dwFlags |= FD_FILESIZE;
				d[i].nFileSizeHigh = static_cast<DWORD>(file.size >> 32);
				d[i].nFileSizeLow = static_cast<DWORD>(file.size);
			}
			if (file.modified_unix_ms > 0) {
				d[i].dwFlags |= FD_WRITESTIME;
				d[i].ftLastWriteTime = filetime(file.modified_unix_ms);
			}
			// HostFileTree kept the path within MAX_PATH with its NUL.
			MultiByteToWideChar(CP_UTF8, 0, file.path.c_str(), -1, d[i].cFileName, MAX_PATH);
		}
		GlobalUnlock(h);
		medium->tymed = TYMED_HGLOBAL;
		medium->hGlobal = h;
		medium->pUnkForRelease = nullptr;
		return S_OK;
	}

	HRESULT contents(LONG index, STGMEDIUM *medium) {
		if (!ensure_files()) {
			return E_FAIL;
		}
		if (index < 0 || static_cast<size_t>(index) >= files_->size() || (*files_)[index].directory) {
			return DV_E_LINDEX;
		}
		const HostFileTree::File &file = (*files_)[index];
		medium->tymed = TYMED_ISTREAM;
		medium->pstm = new FileStream(reads_, {list_.list_id(), file.index}, file);
		medium->pUnkForRelease = nullptr;
		return S_OK;
	}

	LONG refs_ = 1;
	std::shared_ptr<HostFileReads> reads_;
	gdp::session::FileList list_;
	bool tree_;
	std::optional<std::vector<HostFileTree::File>> files_;
	std::vector<Stored> stored_;
	BOOL async_ = TRUE;
	BOOL in_operation_ = FALSE;
};

} // namespace

struct HostFilesClipboard::Impl {
	std::shared_ptr<HostFileReads> reads;
	std::thread thread;
	std::mutex mutex;
	std::condition_variable started;
	bool ready = false;
	HWND window = nullptr; // the thread's; null if it couldn't start
	struct Offer {
		gdp::session::FileList list;
		bool tree = false;
	};
	std::optional<Offer> next; // offer() -> the thread
	IDataObject *current = nullptr; // the thread's: what it last put on the clipboard

	void start();
	void run();
	static LRESULT CALLBACK window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
	void put_offer();
	void take_offer_back();
};

void HostFilesClipboard::Impl::start() {
	thread = std::thread([this] { run(); });
	std::unique_lock<std::mutex> lock(mutex);
	started.wait(lock, [this] { return ready; });
}

void HostFilesClipboard::Impl::run() {
	HRESULT hr = OleInitialize(nullptr);
	HWND hwnd = nullptr;
	if (FAILED(hr)) {
		SLOG_ERROR("files: OleInitialize failed (0x%08lx): the host's files can't be pasted here",
			static_cast<unsigned long>(hr));
	} else {
		HINSTANCE instance = GetModuleHandleW(nullptr);
		WNDCLASSW wc = {};
		wc.lpfnWndProc = window_proc;
		wc.hInstance = instance;
		wc.lpszClassName = L"GhostHostFiles";
		RegisterClassW(&wc); // fails harmlessly when registered already
		hwnd = CreateWindowExW(0, wc.lpszClassName, L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, instance, nullptr);
		if (hwnd) {
			SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(this));
		} else {
			SLOG_ERROR("files: no window for the clipboard (%lu)", GetLastError());
		}
	}
	{
		std::lock_guard<std::mutex> lock(mutex);
		window = hwnd;
		ready = true;
	}
	started.notify_all();
	if (hwnd) {
		MSG msg;
		while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
			TranslateMessage(&msg);
			DispatchMessageW(&msg);
		}
	}
	if (SUCCEEDED(hr)) {
		take_offer_back();
		OleUninitialize();
	}
}

LRESULT CALLBACK HostFilesClipboard::Impl::window_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
	auto *self = reinterpret_cast<Impl *>(GetWindowLongPtrW(hwnd, GWLP_USERDATA));
	switch (msg) {
	case kOfferMessage:
		if (self) {
			self->put_offer();
		}
		return 0;
	case kWithdrawMessage:
		if (self) {
			self->take_offer_back();
		}
		return 0;
	case kQuitMessage:
		if (self) {
			self->take_offer_back();
		}
		DestroyWindow(hwnd);
		PostQuitMessage(0);
		return 0;
	default: return DefWindowProcW(hwnd, msg, wparam, lparam);
	}
}

void HostFilesClipboard::Impl::put_offer() {
	std::optional<Offer> offer;
	{
		std::lock_guard<std::mutex> lock(mutex);
		offer.swap(next);
	}
	if (!offer) {
		return; // a later message took it already
	}
	uint64_t list_id = offer->list.list_id();
	int count = 0;
	for (const gdp::session::FileListEntry &e : offer->list.files()) {
		count += e.parent() == 0;
	}
	auto *object = new DataObject(reads, std::move(offer->list), offer->tree);
	HRESULT hr = E_FAIL;
	for (int i = 0; i < kClipboardTries; i++) {
		hr = OleSetClipboard(object);
		if (hr != CLIPBRD_E_CANT_OPEN) {
			break;
		}
		Sleep(20);
	}
	if (FAILED(hr)) {
		SLOG_ERROR("files: OleSetClipboard failed (0x%08lx)", static_cast<unsigned long>(hr));
		object->Release();
		return;
	}
	if (current) {
		current->Release(); // OLE let go of it when the new one went on
	}
	current = object;
	SLOG_INFO("files: %d of the host's copied file(s) on the clipboard (list %llu)", count,
		(unsigned long long)list_id);
}

void HostFilesClipboard::Impl::take_offer_back() {
	if (!current) {
		return;
	}
	if (OleIsCurrentClipboard(current) == S_OK) {
		for (int i = 0; i < kClipboardTries; i++) {
			if (OleSetClipboard(nullptr) != CLIPBRD_E_CANT_OPEN) {
				break;
			}
			Sleep(20);
		}
	}
	current->Release();
	current = nullptr;
}

HostFilesClipboard::HostFilesClipboard(std::shared_ptr<HostFileReads> reads) : impl_(std::make_unique<Impl>()) {
	impl_->reads = std::move(reads);
}

HostFilesClipboard::~HostFilesClipboard() {
	if (!impl_->thread.joinable()) {
		return;
	}
	if (impl_->window) {
		PostMessageW(impl_->window, kQuitMessage, 0, 0);
	}
	impl_->thread.join();
}

void HostFilesClipboard::offer(const gdp::session::FileList &list, bool tree) {
	if (!impl_->thread.joinable()) {
		impl_->start();
	}
	if (!impl_->window) {
		return; // logged when it failed to start
	}
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->next = Impl::Offer{list, tree};
	}
	PostMessageW(impl_->window, kOfferMessage, 0, 0);
}

void HostFilesClipboard::withdraw() {
	if (!impl_->window) {
		return;
	}
	{
		std::lock_guard<std::mutex> lock(impl_->mutex);
		impl_->next.reset();
	}
	PostMessageW(impl_->window, kWithdrawMessage, 0, 0);
}

bool HostFilesClipboard::on_clipboard() {
	return IsClipboardFormatAvailable(formats().ours) != 0;
}

} // namespace spectre
