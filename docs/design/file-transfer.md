# File transfer

Files both ways behind the `file` capability (gdp-spec.md §7.12): the
client offers each of its files on an additional stream of its own
(§2.2), the host accepts it into the user's download directory; and the
host lists the files its user copies, which the client fetches the same
way, one stream per file. With `file-clipboard` a copy pastes through the
desktop's own file manager both ways, folders included, and with
`file-share` the client's folders show up in the host's file manager:
each side mounts the other's files with FUSE (a Windows client offers
Explorer virtual files instead) and the bytes come over as they are
read ("Paste and shared folders" below).

Code: libgdp's additional streams (`transport.hpp`,
`src/transport/quic_conn.cpp`), `file_transfer.hpp` and `file_list.hpp`,
which both ends share, and `remote_files.hpp` / `remote_mount.hpp`, the
mount; `host/wraith/src/session/file_receiver.*`, `file_sender.*` and
`client_files.*` on the host, and the clipboard sinks
(`session/clipboard_sync.*`, `screencast/*_clipboard.*`) for what was
copied; `client/spectre/src/net/local_files.*`, `clipboard_files.*`,
`host_file_reads.*`, `host_file_tree.*`, `host_files_clipboard_win.*` and
`stream/stream_session.cpp` on spectre.

The client opens every stream, both ways (a fetch is a request on a
stream of the client's, and the host asks for the client's files with a
`FileFetch` the client answers on a stream of its own), so the host never
opens streams and the client keeps granting none.

## Additional streams in libgdp

The transport refused every stream but control and input until this.
What it does now:

- **Credit.** A host grants nothing beyond control and input until
  `allow_streams()`, called once `file` is in effect; the client's
  `open_stream()` waits for that credit like any QUIC stream. The grant
  counts streams open at once: each one that closes is replaced
  (`ngtcp2_conn_extend_max_streams_bidi` from `stream_close`), since
  `MAX_STREAMS` is cumulative and ngtcp2 only replaces streams it never
  reported open.
- **Receive window.** Control and input hand their flow-control credit
  back on receipt, as before. An additional stream hands back its
  stream-level credit only through `Stream::consume()`, so a reader
  slower than the network (a disk) holds the sender back instead of
  filling memory. Connection-level credit still comes back on receipt for
  every stream: with it tied to `consume()` too, four stalled file
  streams could use up the 4 MiB connection window and block the
  client's StatsReports and key presses.
- **Order.** The write loop takes the lowest stream ID with data, so
  control (0) and input (4) always go ahead of file data (8 on).
- **End of a stream.** `on_fin`, `on_reset` and `on_acked` (coalesced to
  one event per dispatch) are reported for additional streams. Dropping a
  `Stream` resets it, except one whose own direction already ended with a
  FIN: that one is let go gracefully, so a last `FileReply` still
  arrives, and the peer is only asked to stop sending. `reset()` cancels.
- **IDs.** Client stream IDs are predicted on the host thread (8, 12,
  ...) and every open goes through the same queue in order. A stream
  cancelled while still waiting for credit is opened anyway when its
  turn comes and reset at once, or every stream queued behind it would
  get the wrong ID.

ngtcp2 1.16 (Ubuntu 26.04's) has no callback for a received
`STOP_SENDING`. A stream that closes with an application error code the
application hasn't heard about yet is reported through `on_reset` when it
closes: that is how the host learns that a client cancelled a fetch whose
request direction had already ended with its FIN (a `RESET_STREAM` after
a FIN changes nothing on the receiving side).

## The host's receiver

`FileReceiver` is made per session when `file` is in effect, and
destroyed with it.

- **Where.** `[files] directory` in wraith.toml, else
  `XDG_DOWNLOAD_DIR` from `user-dirs.dirs`, else `~/Downloads`; it must
  exist and be writable, or the capability isn't offered. Settled as the
  client attaches.
- **Writing.** Off the event loop, on one writer thread per session:
  the event loop also encodes the desktop, and a slow or full disk must
  not stall it. Received bytes are gathered into 256 KiB writes; credit
  goes back to the client only once a write is done. A cancelled
  transfer's file is closed and deleted by whichever of the event loop
  and the writer lets go of it last.
- **Never over an existing file.** The file is written as
  `.ghost-receiving-XXXXXX` (`mkostemp`) in the target directory, then
  renamed into place with `RENAME_NOREPLACE`, trying `name (1).ext`,
  `name (2).ext` ... while the name is taken. Without
  `RENAME_NOREPLACE` (some network file systems) a hard link does the
  same; without links (FAT) a check and a plain rename. A temporary
  file left by a crash is hidden, and the next session doesn't clean it
  up.
- **Telling the client.** `saved` carries the name the file got and the
  folder, as an absolute path, so the client can say where to find it.
- **Permissions and time.** `0666 & ~umask`, like any new file; the
  modification time from the offer.
- **Space.** The offer is refused unless the file plus 64 MiB fits.
- **Notification.** One per batch through
  `org.freedesktop.Notifications`, a second after the last transfer of
  the batch ends ("Received report.pdf", "Received 3 files"), sent
  without waiting for the reply.
- **Protocol errors** (a malformed or oversized opening frame, a byte
  before "accepted") close the connection with `MALFORMED_FRAME` or
  `FRAME_TOO_LARGE`, from an idle callback: the receiver finds out
  inside a stream callback, where the session can't be torn down.

## Copied files, to the client

- **What was copied.** Both clipboard backends read
  `x-special/gnome-copied-files` (Nautilus, first line "copy" or "cut")
  or `text/uri-list` ahead of any text when the selection offers it, and
  the sink turns local `file://` URIs into paths (`copied_file_paths()`
  in libgdp). With a session that can list them, the paths go out as a
  `FileList` and not as text; without one (no `file`, or `[files] send =
  false`) they go as their text, one a line, as before. Copying text
  afterwards takes the list back with an empty one.
- **The list.** `FileSender::set_list()` builds it with
  `gdp::LocalFileList`: anything that isn't a regular file or a folder
  (devices, pipes) or has an unusable name is left out, at most 1000
  copied entries; something copied that is a symbolic link is followed
  (the user picked it). With `file-clipboard`, what is in the copied
  folders follows breadth-first, a folder's entries all or none, until
  the encoded list reaches 512 KiB, and links inside are never followed;
  a folder left out is `unlisted` and listed on request
  (`FileSender::serve_listing()`, appending its entries to the list). The
  latest list and up to 4 earlier ones stay fetchable, each until 10
  minutes after it was replaced or last read from, the one read from
  least recently dropped first, so a paste still reading through the
  client's mount survives a new copy. Only on a session with `clipboard`
  as well as `file`: the list is clipboard content.
- **Sending.** A request is answered from a list still kept, by index:
  the file is opened then, and `FileSending` carries its size at that
  moment. A request may name a range (`offset`, `length`), which is
  what a client reading a file piece by piece needs; the reply says
  where its bytes start and how long the whole file is. A thread of its own reads 256 KiB at a time (`pread`), so a
  cold disk doesn't stall the encoder. A file that comes up short while
  being read is reset rather than sent short. Folders are read off the
  event loop too, on a `gdp::Worker`: building a list (up to 512 KiB of
  entries, some ten thousand stats) and listing a folder on request. A
  list overtaken by a newer copy before it is built is never sent.
- **Pacing.** File data competes with the video for the downlink.
  Nothing more is read while the video's send queue has a backlog
  (`GdpSession::send_queue_clear()`, retried every 10 ms), and the bytes in
  flight follow `FileWindow`: LEDBAT-like, growing while the RTT stays
  within 25 ms of the lowest seen and halving (once a round trip) above
  it, between 256 KiB and 16 MiB. The client's uploads use the same rule.

## Paste and shared folders

The receiving side puts *paths* on its clipboard, as a file manager's
copy does, and the file manager copies from them: so each side mounts the
other's files, and a read in the mount becomes a request over the
connection. This is the design of RDP's file clipboard (xrdp,
gnome-remote-desktop, FreeRDP) and RustDesk's.

- **`gdp::RemoteMount`** (libgdp, Linux, libfuse3's low-level API): a
  read-only mount whose tree and bytes come from its owner. FUSE's loop
  runs on a thread of the mount's own and only queues each request;
  everything else runs on the owner's thread from `dispatch()`, so the
  network code never sees another thread. That thread must never touch
  the mount (a stat there waits for a `dispatch()` that can't come), so
  a copy whose paths lead into our own mount -- a clipboard manager that
  took our offer over -- is ignored on both ends (`contains()`), and
  nothing that reads local folders (a list, a listing, a share's path)
  looks inside one: `gdp::inside_own_mount()` knows this process's
  mounts by name and real path, so a share of `$XDG_RUNTIME_DIR` leaves
  its mount out unlooked at.
- **Reading:** one range per open file, from the first read to the end of
  the file; reads behind it, or more than 2 MiB past what has come, open
  a new range there. The buffer keeps only what a waiting read still
  needs, and what goes to FUSE gives the stream its window back, so a slow
  copy holds the sender back rather than filling memory. A whole file
  read in order costs one request, at link speed rather than one round
  trip per piece (xrdp keeps one piece outstanding at a time).
- **Modes:** files and folders show as 0644/0755 on a read-only mount: a
  copy keeps the mode, and a pasted folder its user can't write into is
  no use.
- **`gdp::RemoteFiles`** fills a mount from the other end: each
  `FileList` becomes `clip/<list_id>/` (the newest 5 kept, as the sender
  keeps them), each share `shares/<name>/`, re-listed when its listing is
  more than 5 s old. It turns a range or a listing into a request through
  a function the owner gives it, and parses the answer (one `FileReply`
  then raw bytes, or listing frames) into the mount. spectre's requests
  open a stream with a `FileRequest`/`FileListingRequest`; wraith's send a
  `FileFetch` and take the client's answering stream from
  `FileReceiver::on_answer`.
- **Clipboards.** spectre offers the mount's paths through SDL3's custom
  clipboard formats (`x-special/gnome-copied-files` saying "copy", then
  `text/uri-list` and the paths as text), produced when a paste asks, and
  ignores the clipboard update its own offer causes (the event's `owner`).
  wraith's sinks take the selection with the same formats
  (`ClipboardSink::set_files()`): mutter's `SetSelection` (whose echo
  says session-is-owner), or a data-control source (whose echo is
  compared with what it offers). Always a copy, never a cut: nothing
  deletes an original across.
- **Windows** has no FUSE, so spectre puts the host's list on the
  clipboard as Explorer's virtual files instead of paths
  (`host_files_clipboard_win.*`): an `IDataObject` offering
  `FILEGROUPDESCRIPTORW` (every file and folder by its path from the
  paste target), `FILECONTENTS` (an `IStream` per file), a copy
  `Preferred DropEffect`, `Ghost.HostFiles` (so the clipboard update its
  own offer causes, which has no SDL owner, is ignored) and
  `ExcludeClipboardContentFromMonitorProcessing` (out of Win+V's history),
  with `IDataObjectAsyncCapability` so Explorer copies off its UI thread.
  No `CF_HDROP`, and nothing fetched until a paste asks: the descriptors
  are built then (`HostFileTree`), first listing every folder the list
  left unlisted (at most `kMaxFileListTotal` entries and 60 s, or the
  paste fails rather than leaving half a tree), and leaving out names
  Windows can't hold (`gdp::windows_safe()`), names taken twice in a
  folder ignoring case, and paths past `MAX_PATH`, logged.
  - **Threads.** Explorer's calls come over COM to the thread that owns
    the object's apartment: one of its own (an STA with a message-only
    window), which blocks in a read until the host's bytes come, one read
    at a time. It never touches the connection: it posts each read to
    `HostFileReads`, which the main thread dispatches every pass, opening
    a "file" stream as the mount's requests do and handing the bytes
    across. A stream's credit goes back only as the reading thread takes
    the bytes, so a slow paste target holds the host back. A request the
    host leaves unanswered for `kFileReplyTimeoutMs`, or goes quiet on
    that long while its reader waits, fails; Explorer reports it.
  - **Lifetime.** Disconnect and session end fail every read at once,
    then take the offer back (`OleSetClipboard(nullptr)` if it is still
    ours; never `OleFlushClipboard`, which would fetch every file). A new
    list replaces the offer; one with no files leaves it, as on Linux.
- **The client's copies.** spectre reads copied files from the clipboard
  (SDL's mime types; Explorer's `CF_HDROP` on Windows), sends them as a
  `FileList` built the same way, and answers `FileFetch` from
  `LocalFiles`, by list and index, with the host's lifetime rule. Its
  disk work -- building lists, resolving and listing paths, opening
  files and reading them a piece at a time -- runs on a `gdp::Worker`,
  so a slow or hung drive (one of `-F`'s removable ones) never stalls
  the picture or input.
- **Shared folders** (spectre `-S`, and `-F` for the home folder and
  removable drives, or on Windows the user folder and every drive,
  `my_folders.*`, looked at
  again every 3 s): `LocalFiles` answers by path, through
  `gdp::resolve_beneath()` (no empty parts, `.`, `..` or symbolic links
  on the way, and unless `-I` nothing hidden: `gdp::hidden_local()`, a
  leading dot, or the hidden or system attribute on Windows, `UF_HIDDEN`
  on macOS). Never `/`: the user's keys, and full of links and devices a
  share leaves out anyway. wraith mounts each under
  `$XDG_RUNTIME_DIR/ghost/files/shares/` -- not under `$HOME`, where
  Baloo and backup tools would crawl a remote mount -- and adds a GTK
  bookmark and a KDE Places entry (`file_bookmarks.*`), removed with the
  share and, after a crash, at the next start.

## Limitations

- No resumption: a connection lost mid-transfer loses the partial file.
  Uploads (drag and drop) don't take folders.
- On Windows, every read of a paste runs on the clipboard's one thread:
  while it waits on the host, other calls into the offer (another
  program asking what the clipboard holds) wait too. Explorer copies one
  file at a time, so a paste itself isn't slowed. Paths past `MAX_PATH`
  are left out.
- macOS has neither FUSE nor virtual files, so the host's copies can't
  be pasted there; `NSFilePromiseProvider` would be the way, reading
  through the same `HostFileReads`.
- Sandboxed (Flatpak) file managers may not see a mount under
  `$XDG_RUNTIME_DIR`.
- File data and the client's StatsReports share the client's uplink. A
  client that sends faster than its uplink carries delays its reports
  and makes the host's rate control think the path got worse; pacing is
  the client's job.
