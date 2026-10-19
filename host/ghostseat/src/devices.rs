// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Virtual input devices for this session, the root-only half of gamepad
// forwarding (docs/design/audio-cursor-gamepad.md#gamepads).
//
// wraith runs as the session user and a ghost session has no seat, so
// two things it cannot do itself happen here. /dev/uinput and /dev/uhid
// are root's -- deliberately not opened up with a group, since they are
// the right to create arbitrary input devices, keyboards included -- so
// ghostseat creates the device. And the nodes that result are, by
// default, ACL'd by logind to the *console* seat's active user (udev's
// input_id tags any joystick `uaccess`, Steam's rules tag Sony and Valve
// hidraw nodes, and a virtual device has no seated parent so it lands on
// seat0) and unreachable by the session user, so
// packaging/system/udev/72-ghost-input.rules moves ghost's devices off
// seat0 and ghostseat chowns every node they produce to the session's
// uid.
//
// wraith never holds the device's own fd: that fd is the device's
// control handle (UI_DEV_DESTROY and a new UI_DEV_SETUP, or UHID_DESTROY
// and a new UHID_CREATE2, would make it any input device at all,
// keyboards included, and the console's keyboard and SysRq handlers take
// input from every device whatever its seat). What wraith gets over the
// control socket (SCM_RIGHTS) is one end of a SOCK_SEQPACKET socketpair;
// ghostseat keeps the device fd and relays each packet after checking
// it: input_event batches for a gamepad, UHID_INPUT2 and report replies
// for a raw controller, which it holds back until the driver's verdict.
// Output events from a uhid device go back the same way. wraith closing
// its end destroys the device.
//
// Three kinds:
// - KIND_GAMEPAD, a uinput Xbox 360-layout pad (gdp-spec.md §8.5).
// - KIND_HID, a uhid device with the client controller's own identity
//   and report descriptor (§8.6), so the host's own driver for it binds.
//   The driver probes after UHID_CREATE2 returns, and a probe can ask
//   for reports only wraith (from the client) can answer, so the relay
//   runs at once; ghostseat waits for the driver's bind, checks what the
//   driver created, and destroys the device if it isn't a game
//   controller (verify_hid).
// - KIND_SECURITY_KEY, a uhid FIDO device (§8.7, ADR 0015) with the
//   client key's vendor, product and name but FIDO_DESCRIPTOR, never the
//   client's. Only hid-generic may bind and it must make no input device
//   (verify_security_key); the relay passes only 64-byte CTAPHID packets
//   in and output reports out, and fails the driver's GET_REPORT and
//   SET_REPORT itself, since CTAPHID uses neither.
//
// Nodes are chowned from a udev monitor (monitor_loop) rather than per
// device: the chown must come *after* udev has applied the rule (the
// node exists in devtmpfs before udevd sees it, and udevd applies the
// rule's MODE on the add event, resetting anything done earlier), and
// uhid drivers add nodes whenever they like -- hid-steam re-registers its
// gamepad each time Steam closes the hidraw node. udev's monitor
// broadcasts each event after its rules ran, which is exactly the
// moment. The uid comes from the device's phys, ghost/uid-<uid>/...,
// which only root can set on a uinput or uhid device; every ghostseat
// instance sees every event and handles its own uid's.
use std::collections::HashMap;
use std::ffi::CString;
use std::io::{IoSlice, IoSliceMut};
use std::mem::size_of;
use std::ops::RangeInclusive;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ipc::control::{
    control_envelope::Msg as ControlMsg, create_device, ControlEnvelope, ControlError, CreateDevice, DeviceCreated,
    DeviceVerified, HidIdentity,
};
use ipc::framing::{frame_bytes, write_frame};
use nix::sys::socket::{
    bind, recv, recvmsg, send, sendmsg, setsockopt, socket, socketpair, sockopt, AddressFamily, ControlMessage,
    ControlMessageOwned, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType, UnixAddr, UnixCredentials,
};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncWriteExt, Interest};
use tokio::net::UnixStream;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};

const UINPUT_PATH: &str = "/dev/uinput";
const UHID_PATH: &str = "/dev/uhid";
// Either location an admin might have put the packaged rule
// (packaging/system/udev/72-ghost-input.rules; the install puts it in the first).
const RULE_PATHS: [&str; 2] = ["/usr/lib/udev/rules.d/72-ghost-input.rules", "/etc/udev/rules.d/72-ghost-input.rules"];
// The rule's uhid line. Without it a uhid device's nodes stay on seat0
// (their phys is empty), so raw controllers need it there.
const RULE_HID_MARKER: &str = "HID_PHYS=ghost/";
// libgdp's gdp::kMaxGamepads: slots a client may name.
pub const MAX_GAMEPADS: u32 = 4;
// gdp-spec.md §8.7's security-key slots.
pub const MAX_SECURITY_KEYS: u32 = 2;
// What the udev rule keys on (ATTRS{phys}=="ghost/*", and HID_PHYS for
// uhid), and what it sets (ENV{ID_SEAT}="ghost") -- checked on each event
// as proof the rule ran.
const PHYS_PREFIX: &str = "ghost";
const SEAT: &str = "ghost";
// How long a uhid device's driver gets to bind. Its probe may wait on
// the client for several reports, each up to the kernel's 5 s.
const BIND_WAIT: Duration = Duration::from_secs(10);

// Linux ioctl request layout (asm-generic/ioctl.h, x86_64/arm64):
// dir:2 | size:14 | type:8 | nr:8. libc has the uinput structs but not
// the UI_* request codes.
const fn ioc(dir: libc::c_ulong, ty: u8, nr: u8, size: usize) -> libc::c_ulong {
    (dir << 30) | ((size as libc::c_ulong) << 16) | ((ty as libc::c_ulong) << 8) | (nr as libc::c_ulong)
}
const IOC_WRITE: libc::c_ulong = 1;
const IOC_READ: libc::c_ulong = 2;
const UI_DEV_CREATE: libc::c_ulong = ioc(0, b'U', 1, 0);
const UI_DEV_SETUP: libc::c_ulong = ioc(IOC_WRITE, b'U', 3, size_of::<libc::uinput_setup>());
const UI_ABS_SETUP: libc::c_ulong = ioc(IOC_WRITE, b'U', 4, size_of::<libc::uinput_abs_setup>());
const UI_SET_EVBIT: libc::c_ulong = ioc(IOC_WRITE, b'U', 100, size_of::<libc::c_int>());
const UI_SET_KEYBIT: libc::c_ulong = ioc(IOC_WRITE, b'U', 101, size_of::<libc::c_int>());
const UI_SET_ABSBIT: libc::c_ulong = ioc(IOC_WRITE, b'U', 103, size_of::<libc::c_int>());
const UI_SET_PHYS: libc::c_ulong = ioc(IOC_WRITE, b'U', 108, size_of::<*const libc::c_char>());
const SYSNAME_LEN: usize = 64;
const UI_GET_SYSNAME: libc::c_ulong = ioc(IOC_READ, b'U', 44, SYSNAME_LEN);

// input-event-codes.h. The gamepad is an Xbox 360 layout because that is
// the one every game and SDL's own controller database already knows:
// eleven buttons, two sticks, two analog triggers, a hat for the d-pad.
// BTN_X/BTN_Y rather than the compass aliases, matching what the kernel's
// xpad driver reports and therefore what SDL maps on the host.
const EV_SYN: libc::c_int = 0x00;
const EV_KEY: libc::c_int = 0x01;
const EV_ABS: libc::c_int = 0x03;
const SYN_REPORT: u16 = 0;
const INPUT_EVENT_SIZE: usize = size_of::<libc::input_event>();
// The most input_events one packet from wraith may carry: a whole
// gamepad snapshot is 19 plus the SYN.
const MAX_BATCH: usize = 64;
const BUS_VIRTUAL: u16 = 0x06;
const GAMEPAD_KEYS: [libc::c_int; 11] = [
    0x130, // BTN_A (BTN_SOUTH)
    0x131, // BTN_B (BTN_EAST)
    0x133, // BTN_X (BTN_NORTH)
    0x134, // BTN_Y (BTN_WEST)
    0x136, // BTN_TL
    0x137, // BTN_TR
    0x13a, // BTN_SELECT
    0x13b, // BTN_START
    0x13c, // BTN_MODE
    0x13d, // BTN_THUMBL
    0x13e, // BTN_THUMBR
];
// (code, min, max, fuzz, flat): sticks as xpad reports them, triggers
// 0..255, hat -1..1. These ranges are also what wraith's
// session/gamepad_evdev.cpp scales the wire's floats into.
const GAMEPAD_AXES: [(u16, i32, i32, i32, i32); 8] = [
    (0x00, -32768, 32767, 16, 128), // ABS_X
    (0x01, -32768, 32767, 16, 128), // ABS_Y
    (0x03, -32768, 32767, 16, 128), // ABS_RX
    (0x04, -32768, 32767, 16, 128), // ABS_RY
    (0x02, 0, 255, 0, 0),           // ABS_Z (left trigger)
    (0x05, 0, 255, 0, 0),           // ABS_RZ (right trigger)
    (0x10, -1, 1, 0, 0),            // ABS_HAT0X
    (0x11, -1, 1, 0, 0),            // ABS_HAT0Y
];
// Microsoft's Xbox 360 wired pad, so SDL on the host picks its stock
// mapping for the device; the name is ours so the udev rule's
// ATTRS{phys} match isn't the only thing identifying it in logs.
const VENDOR_ID: u16 = 0x045e;
const PRODUCT_ID: u16 = 0x028e;
const VERSION: u16 = 0x0110; // the real pad's bcdDevice
const DEVICE_NAME: &str = "Ghost Gamepad";

// linux/uhid.h. Every event is a u32 type and a packed union; writes
// may be shorter than the union, reads return at most UHID_EVENT_SIZE.
const UHID_DESTROY: u32 = 1;
const UHID_START: u32 = 2;
const UHID_STOP: u32 = 3;
const UHID_OPEN: u32 = 4;
const UHID_CLOSE: u32 = 5;
const UHID_OUTPUT: u32 = 6;
const UHID_GET_REPORT: u32 = 9;
const UHID_CREATE2: u32 = 11;
const UHID_SET_REPORT: u32 = 13;
// What wraith may write: an input report, and the replies to the
// driver's GET_REPORT / SET_REPORT requests.
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_INPUT2: u32 = 12;
const UHID_SET_REPORT_REPLY: u32 = 14;
// sizeof(struct uhid_event): uhid_create2_req is the union's largest
// member at 4372 bytes, padded to 4376 by the legacy uhid_create_req's
// pointer.
const UHID_EVENT_SIZE: usize = 4 + 4376;
const UHID_NAME_LEN: usize = 128;
const UHID_PHYS_LEN: usize = 64;
const UHID_UNIQ_LEN: usize = 64;
pub const HID_MAX_DESCRIPTOR_SIZE: usize = 4096;
const BUS_USB: u32 = 0x03;
const BUS_BLUETOOTH: u32 = 0x05;

// gdp-spec.md §8.7: every security key is presented with this, the FIDO
// Alliance page's CTAPHID collection with 64-byte input and output
// reports and no report IDs -- what every key in use reports anyway, so
// nothing the client sends reaches the kernel's HID parser.
const FIDO_DESCRIPTOR: [u8; 34] = [
    0x06, 0xd0, 0xf1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (CTAPHID)
    0xa1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xff, 0x00, //   Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xc0, // End Collection
];
// A CTAPHID packet: one report of FIDO_DESCRIPTOR's.
const FIDO_PACKET: usize = 64;
// The only driver that may bind to a security key: FIDO_DESCRIPTOR gives
// it nothing to map, so it makes a hidraw node and no input device.
const SECURITY_KEY_DRIVER: &str = "hid-generic";

// What a raw controller may bind to (the hid_driver's name, as the
// device's DRIVER property shows it). Everything else -- vendor drivers
// for keyboards, receivers that spawn child devices, ... -- is refused,
// whatever its descriptor said.
const HID_DRIVERS: [&str; 6] = ["hid-generic", "playstation", "sony", "steam", "nintendo", "microsoft"];
// input-event-codes.h event types an input device made from a raw
// controller may report: no EV_REL (pointers), EV_SW (lid and power
// switches logind acts on), EV_SND or EV_REP (keyboards).
const HID_EV_ALLOWED: [usize; 6] = [0x00, 0x01, 0x03, 0x04, 0x11, 0x15]; // SYN KEY ABS MSC LED FF
// ...and the keys: the misc/mouse/joystick/gamepad/digitizer buttons, the
// d-pad buttons and BTN_TRIGGER_HAPPY. Below BTN_MISC (0x100) is where
// the console's keyboard handler and SysRq attach; 0x160 up are keys
// (KEY_POWER2 among them).
const HID_KEYS_ALLOWED: [RangeInclusive<usize>; 3] = [0x100..=0x15f, 0x220..=0x223, 0x2c0..=0x2e7];

static MONITOR_RUNNING: AtomicBool = AtomicBool::new(false);
// The session's uid: the only owner whose nodes this instance chowns.
static OWNER_UID: AtomicU32 = AtomicU32::new(u32::MAX);
// Makes each uhid device's phys unique, so a slot replaced while its old
// device is still being checked never shares a pending-bind key with it.
static HID_SEQ: AtomicU64 = AtomicU64::new(0);

/// uhid devices waiting for their driver to bind, by phys: the monitor
/// sends the bound device's DEVPATH and DRIVER.
fn pending_binds() -> &'static Mutex<HashMap<String, oneshot::Sender<(String, String)>>> {
    static PENDING: OnceLock<Mutex<HashMap<String, oneshot::Sender<(String, String)>>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Whether CreateDevice can make a uinput gamepad on this host:
/// /dev/uinput is present, the seat rule is installed and the udev
/// monitor that chowns the nodes is running. Reported in SessionInit so
/// wraith offers the "gamepad" capability only when it's real.
pub fn available() -> bool {
    Path::new(UINPUT_PATH).exists() && rule_text().is_some() && MONITOR_RUNNING.load(Ordering::Relaxed)
}

/// The same for KIND_HID and KIND_SECURITY_KEY: /dev/uhid, and a rule
/// with its uhid line. Gates the "hid" and "security-key" capabilities.
pub fn uhid_available() -> bool {
    Path::new(UHID_PATH).exists()
        && rule_text().is_some_and(|t| t.contains(RULE_HID_MARKER))
        && MONITOR_RUNNING.load(Ordering::Relaxed)
}

/// Logged once at session start, since a missing rule is an install
/// problem the admin wants to hear about.
pub fn log_availability() {
    if !MONITOR_RUNNING.load(Ordering::Relaxed) {
        warn!("devices: no udev monitor -- gamepad forwarding disabled");
    } else if rule_text().is_none() {
        warn!(paths = ?RULE_PATHS, "devices: udev seat rule not installed -- gamepad forwarding disabled");
    } else {
        if !Path::new(UINPUT_PATH).exists() {
            warn!(path = UINPUT_PATH, "devices: no uinput device -- standard gamepads disabled (modprobe uinput?)");
        }
        if !Path::new(UHID_PATH).exists() {
            warn!(path = UHID_PATH, "devices: no uhid device -- raw controllers disabled (modprobe uhid?)");
        } else if !uhid_available() {
            warn!(paths = ?RULE_PATHS, "devices: the udev seat rule lacks its uhid line -- raw controllers disabled");
        }
        if available() || uhid_available() {
            info!(standard = available(), raw = uhid_available(), "devices: gamepad forwarding available");
        }
        if uhid_available() {
            info!("devices: security-key forwarding available");
        }
    }
}

fn rule_text() -> Option<String> {
    RULE_PATHS.iter().find_map(|p| std::fs::read_to_string(p).ok())
}

/// The devices this session has live, by kind and slot. Any process of
/// the user can send CreateDevice, so the bound on what a session holds
/// is enforced here, not trusted to wraith: a create for an occupied
/// slot cancels the task serving it (which drops the device fd and so
/// destroys the device) and waits for it to be gone before creating.
/// With MAX_GAMEPADS slots per kind (MAX_SECURITY_KEYS for keys) that is
/// also the bound on tasks in flight, uhid creates waiting on BIND_WAIT
/// included.
#[derive(Default)]
struct Slots {
    gamepad: [Option<Slot>; MAX_GAMEPADS as usize],
    hid: [Option<Slot>; MAX_GAMEPADS as usize],
    key: [Option<Slot>; MAX_SECURITY_KEYS as usize],
}

/// A task serving a slot: dropping `cancel` cancels it, and `done` closes
/// when it has ended and released what it held.
struct Slot {
    cancel: oneshot::Sender<()>,
    done: oneshot::Receiver<()>,
}

/// What a task holds while it serves a slot. `_done` closes the slot's
/// `done` receiver when the task ends, however it ends.
struct Claim {
    _done: oneshot::Sender<()>,
}

fn slots() -> &'static Mutex<Slots> {
    static SLOTS: OnceLock<Mutex<Slots>> = OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(Slots::default()))
}

/// Takes `index` of `kind`, cancelling and waiting out whatever served
/// it before. Returns the claim and the receiver that fires when a later
/// claim on the same slot cancels this one.
async fn claim_slot(kind: create_device::Kind, index: u32) -> (Claim, oneshot::Receiver<()>) {
    let (cancel_tx, cancel_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let previous = {
        let mut slots = slots().lock().unwrap();
        let table: &mut [Option<Slot>] = match kind {
            create_device::Kind::Hid => &mut slots.hid,
            create_device::Kind::SecurityKey => &mut slots.key,
            _ => &mut slots.gamepad,
        };
        table[index as usize].replace(Slot { cancel: cancel_tx, done: done_rx })
    };
    if let Some(previous) = previous {
        drop(previous.cancel);
        // Err once the previous task has dropped its Claim, i.e. ended.
        let _ = previous.done.await;
        debug!(?kind, index, "devices: replaced the device in this slot");
    }
    (Claim { _done: done_tx }, cancel_rx)
}

/// Serves one CreateDevice on `stream`, which it owns from here on: the
/// reply is DeviceCreated plus the fd, or a ControlError; for KIND_HID and
/// KIND_SECURITY_KEY a DeviceVerified or ControlError follows once the
/// driver has bound. Run
/// as its own task: it lives as long as the device does, since the relay
/// runs inside it (so cancelling the task is destroying the device).
pub async fn handle_create(mut stream: UnixStream, uid: u32, username: String, req: CreateDevice) {
    let kind = create_device::Kind::try_from(req.kind).unwrap_or(create_device::Kind::Unspecified);
    let checked = match kind {
        create_device::Kind::Gamepad | create_device::Kind::Hid if req.index >= MAX_GAMEPADS => {
            Err(anyhow::anyhow!("gamepad index {} out of range (max {})", req.index, MAX_GAMEPADS - 1))
        }
        create_device::Kind::SecurityKey if req.index >= MAX_SECURITY_KEYS => Err(anyhow::anyhow!(
            "security key index {} out of range (max {})",
            req.index,
            MAX_SECURITY_KEYS - 1
        )),
        create_device::Kind::Gamepad | create_device::Kind::Hid | create_device::Kind::SecurityKey => Ok(()),
        other => Err(anyhow::anyhow!("unsupported device kind {other:?}")),
    };
    let result = match checked {
        Ok(()) => {
            let (_claim, mut cancelled) = claim_slot(kind, req.index).await;
            let serve = async {
                match kind {
                    create_device::Kind::Hid => serve_hid(&mut stream, uid, &username, req).await,
                    create_device::Kind::SecurityKey => serve_security_key(&mut stream, uid, &username, req).await,
                    _ => serve_gamepad(&mut stream, uid, &username, req).await,
                }
            };
            tokio::select! {
                result = serve => result,
                _ = &mut cancelled => {
                    debug!(uid, username, ?kind, "devices: device replaced by a new CreateDevice");
                    return;
                }
            }
        }
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        warn!(uid, username, error = %e, "devices: CreateDevice failed");
        let reply = ControlEnvelope { msg: Some(ControlMsg::Error(ControlError { message: format!("{e:#}"), code: 0 })) };
        if let Err(e) = write_frame(&mut stream, &reply).await {
            debug!(uid, username, error = %e, "devices: failed to send the CreateDevice error reply");
        }
    }
}

/// Creates the pad, hands wraith its socket, then relays for the pad's
/// life. Returns when wraith closes its end.
async fn serve_gamepad(stream: &mut UnixStream, uid: u32, username: &str, req: CreateDevice) -> Result<()> {
    if !available() {
        bail!("virtual gamepads are not available on this host (uinput, the udev rule or the udev monitor is missing)");
    }
    let phys = format!("{PHYS_PREFIX}/uid-{uid}/pad{}", req.index);
    let (fd, sysname) = tokio::task::spawn_blocking(move || create_gamepad(&phys))
        .await
        .context("device-create task panicked")?
        .context("creating the uinput gamepad")?;
    info!(uid, username, index = req.index, client_name = %req.name, sysname = %sysname, "devices: gamepad created");
    let (ours, theirs) = pair().context("socketpair for the gamepad")?;
    send_created(stream, &sysname, &theirs).await;
    drop(theirs);
    // The reply is the last thing this connection carries.
    let _ = stream.shutdown().await;
    // wraith's end is the device's life from now on: the relay ends, and
    // drops the uinput fd, when wraith closes it.
    relay_gamepad(ours, fd, uid, req.index).await;
    Ok(())
}

/// Removes a pending-bind entry when the create that registered it ends,
/// verdict or not.
struct PendingBind(String);

impl Drop for PendingBind {
    fn drop(&mut self) {
        pending_binds().lock().unwrap().remove(&self.0);
    }
}

async fn serve_hid(stream: &mut UnixStream, uid: u32, username: &str, req: CreateDevice) -> Result<()> {
    if !uhid_available() {
        bail!("raw controllers are not available on this host (uhid, the udev rule or the udev monitor is missing)");
    }
    let ident = req.hid.clone().context("KIND_HID without a HidIdentity")?;
    check_identity(&req.name, &ident)?;
    let seq = HID_SEQ.fetch_add(1, Ordering::Relaxed);
    let phys = format!("{PHYS_PREFIX}/uid-{uid}/pad{}/{seq}", req.index);

    // Registered before the create, so the bind can't come first.
    let (bind_tx, bind_rx) = oneshot::channel();
    pending_binds().lock().unwrap().insert(phys.clone(), bind_tx);
    let _pending = PendingBind(phys.clone());
    create_and_verify(stream, uid, username, &req, &ident, &phys, bind_rx, UhidKind::Controller).await
}

async fn serve_security_key(stream: &mut UnixStream, uid: u32, username: &str, req: CreateDevice) -> Result<()> {
    if !uhid_available() {
        bail!("security keys are not available on this host (uhid, the udev rule or the udev monitor is missing)");
    }
    let ident = security_key_identity(&req.name, req.hid.as_ref().context("KIND_SECURITY_KEY without a HidIdentity")?)?;
    let seq = HID_SEQ.fetch_add(1, Ordering::Relaxed);
    let phys = format!("{PHYS_PREFIX}/uid-{uid}/key{}/{seq}", req.index);

    let (bind_tx, bind_rx) = oneshot::channel();
    pending_binds().lock().unwrap().insert(phys.clone(), bind_tx);
    let _pending = PendingBind(phys.clone());
    create_and_verify(stream, uid, username, &req, &ident, &phys, bind_rx, UhidKind::SecurityKey).await
}

/// Which uhid device a relay and its verdict are for: what wraith may
/// write, what goes back to it, and what the driver must have made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UhidKind {
    Controller,
    SecurityKey,
}

impl UhidKind {
    fn label(self) -> &'static str {
        match self {
            UhidKind::Controller => "raw controller",
            UhidKind::SecurityKey => "security key",
        }
    }
}

/// Creates the uhid device, hands wraith its socket and runs the relay
/// alongside the wait for the driver's verdict: the relay must answer
/// the driver's probe requests before any verdict exists. Returns the
/// verdict's error once the relay has ended, or Ok when wraith closes.
async fn create_and_verify(
    stream: &mut UnixStream,
    uid: u32,
    username: &str,
    req: &CreateDevice,
    ident: &HidIdentity,
    phys: &str,
    bind_rx: oneshot::Receiver<(String, String)>,
    kind: UhidKind,
) -> Result<()> {
    let fd = {
        let (name, phys, ident) = (req.name.clone(), phys.to_string(), ident.clone());
        tokio::task::spawn_blocking(move || create_hid(&name, &phys, &ident))
            .await
            .context("device-create task panicked")?
            .context("creating the uhid device")?
    };
    let keep = fd.try_clone().context("duplicating the uhid fd")?;
    let what = kind.label();
    info!(uid, username, index = req.index, name = %req.name, phys,
        id = format!("{:04x}:{:04x}:{:04x}", ident.bus, ident.vendor_id, ident.product_id),
        "devices: {what} created, waiting for its driver");
    let (ours, theirs) = pair().with_context(|| format!("socketpair for the {what}"))?;
    send_created(stream, phys, &theirs).await;
    drop(theirs);
    let verified = Arc::new(AtomicBool::new(false));
    let relay = relay_hid(ours, fd, verified.clone(), uid, req.index, kind);

    let verdict = async {
        let verdict = match tokio::time::timeout(BIND_WAIT, bind_rx).await {
            Ok(Ok((devpath, driver))) => {
                let d = driver.clone();
                let verify = move || match kind {
                    UhidKind::Controller => verify_hid(&devpath, &d),
                    UhidKind::SecurityKey => verify_security_key(&devpath, &d),
                };
                match tokio::task::spawn_blocking(verify).await {
                    Ok(r) => r.map(|()| driver),
                    Err(e) => Err(anyhow::anyhow!("verify task panicked: {e}")),
                }
            }
            Ok(Err(_)) => Err(anyhow::anyhow!("the udev monitor stopped")),
            Err(_) => Err(anyhow::anyhow!("no driver bound within {BIND_WAIT:?}")),
        };
        match verdict {
            Ok(driver) => {
                info!(uid, username, index = req.index, phys, driver, "devices: {what} verified");
                verified.store(true, Ordering::Release);
                let reply = ControlEnvelope { msg: Some(ControlMsg::DeviceVerified(DeviceVerified { driver })) };
                if let Err(e) = write_frame(stream, &reply).await {
                    debug!(uid, username, error = %e, "devices: failed to send DeviceVerified");
                }
                Ok(())
            }
            Err(e) => {
                // Through this reference to the device: the relay's reads
                // then fail and it closes wraith's end, whose writes fail.
                if let Err(e) = write_uhid(&keep, &uhid_event(UHID_DESTROY)) {
                    warn!(uid, username, phys, error = %e, "devices: UHID_DESTROY failed");
                }
                Err(e.context(format!("{what} refused")))
            }
        }
    };
    let ((), verdict) = tokio::join!(relay, verdict);
    verdict
}

/// The identity a client sent, before any of it reaches the kernel.
fn check_identity(name: &str, ident: &HidIdentity) -> Result<()> {
    if ident.bus != BUS_USB && ident.bus != BUS_BLUETOOTH {
        bail!("bus {:#x} is neither USB nor Bluetooth", ident.bus);
    }
    if ident.vendor_id > 0xffff || ident.product_id > 0xffff {
        bail!("vendor/product ID out of range");
    }
    let rd = ident.report_descriptor.len();
    if rd == 0 || rd > HID_MAX_DESCRIPTOR_SIZE {
        bail!("report descriptor of {rd} bytes (1..={HID_MAX_DESCRIPTOR_SIZE})");
    }
    if name.len() >= UHID_NAME_LEN || name.chars().any(char::is_control) {
        bail!("unusable device name");
    }
    if ident.uniq.len() >= UHID_UNIQ_LEN || !ident.uniq.bytes().all(|b| b.is_ascii_graphic()) {
        bail!("unusable uniq");
    }
    screen_descriptor(&ident.report_descriptor)
}

/// The identity a security key is created with: the client's vendor,
/// product, release and name, on USB, with FIDO_DESCRIPTOR. wraith sends
/// nothing else; anything more is refused rather than ignored, so that a
/// wraith that thinks it is sending a descriptor finds out.
fn security_key_identity(name: &str, sent: &HidIdentity) -> Result<HidIdentity> {
    if sent.bus != 0 || !sent.uniq.is_empty() || !sent.report_descriptor.is_empty() {
        bail!("a security key's identity carries only vendor, product and version");
    }
    let ident = HidIdentity {
        bus: BUS_USB,
        vendor_id: sent.vendor_id,
        product_id: sent.product_id,
        version: sent.version,
        uniq: String::new(),
        report_descriptor: FIDO_DESCRIPTOR.to_vec(),
    };
    check_identity(name, &ident)?;
    Ok(ident)
}

// HID usage pages and usages the screen refuses (HID Usage Tables 1.4).
const PAGE_GENERIC_DESKTOP: u32 = 0x01;
const PAGE_KEYBOARD: u32 = 0x07;
const PAGE_CONSUMER: u32 = 0x0c;
// Generic Desktop: Pointer, Mouse, Keyboard, Keypad as a top-level
// collection's usage, and the System Control block (0x80 System Control,
// 0x81 Power Down, 0x82 Sleep, 0x83 Wake Up, ... 0x8f) anywhere.
const DESKTOP_TOP_LEVEL_REFUSED: [u32; 4] = [0x01, 0x02, 0x06, 0x07];
const DESKTOP_SYSTEM_CONTROL: RangeInclusive<u32> = 0x80..=0x8f;

/// A filter in front of the kernel's HID parser, not the policy
/// (verify_hid is: a driver picked by vendor and product id can create
/// what the descriptor doesn't show). Walks the short items and refuses
/// a descriptor that names a keyboard, consumer-control or system-control
/// usage, or a mouse, pointer, keyboard or keypad application collection,
/// before any of it reaches the kernel as root; what's left is what a
/// game controller uses (Generic Desktop axes and Game Pad/Joystick,
/// Button, LED, Physical Interface, vendor pages). Long items (nothing
/// defines any) and items that run past the end are refused too.
fn screen_descriptor(rd: &[u8]) -> Result<()> {
    let mut page: u32 = 0;
    let mut usages: Vec<u32> = Vec::new(); // (page << 16) | usage, the locals since the last main item
    let mut depth = 0u32;
    let mut i = 0;
    while i < rd.len() {
        let prefix = rd[i];
        if prefix == 0xfe {
            bail!("report descriptor has a long item at byte {i}");
        }
        let size = match prefix & 0x3 {
            3 => 4,
            n => n as usize,
        };
        let (ty, tag) = ((prefix >> 2) & 0x3, prefix >> 4);
        let data = rd
            .get(i + 1..i + 1 + size)
            .with_context(|| format!("report descriptor item at byte {i} runs past the end"))?;
        let value = data.iter().rev().fold(0u32, |v, &b| (v << 8) | u32::from(b));
        i += 1 + size;
        match (ty, tag) {
            // Global: Usage Page.
            (1, 0) => page = value,
            // Local: Usage, Usage Minimum, Usage Maximum. A 4-byte usage
            // carries its own page in the high half.
            (2, 0) | (2, 1) | (2, 2) => {
                let full = if size == 4 { value } else { (page << 16) | value };
                refuse_usage(full)?;
                usages.push(full);
            }
            // Main: Collection (data 1 = Application) and End Collection.
            (0, 0xa) => {
                if depth == 0 && value == 0x01 {
                    if let Some(&u) = usages.last() {
                        if u >> 16 == PAGE_GENERIC_DESKTOP && DESKTOP_TOP_LEVEL_REFUSED.contains(&(u & 0xffff)) {
                            let usage = u & 0xffff;
                            bail!("report descriptor's application collection is Generic Desktop usage {usage:#x}");
                        }
                    }
                }
                depth += 1;
                usages.clear();
            }
            (0, 0xc) => {
                depth = depth.saturating_sub(1);
                usages.clear();
            }
            // Other main items (Input, Output, Feature) consume the locals.
            (0, _) => usages.clear(),
            _ => {}
        }
    }
    Ok(())
}

fn refuse_usage(full: u32) -> Result<()> {
    let (page, usage) = (full >> 16, full & 0xffff);
    match page {
        PAGE_KEYBOARD => bail!("report descriptor uses the Keyboard/Keypad page"),
        PAGE_CONSUMER => bail!("report descriptor uses the Consumer page"),
        PAGE_GENERIC_DESKTOP if DESKTOP_SYSTEM_CONTROL.contains(&usage) => {
            bail!("report descriptor uses Generic Desktop System Control usage {usage:#x}")
        }
        _ => Ok(()),
    }
}

/// DeviceCreated with wraith's end of the socketpair attached. On failure
/// the caller drops that end, the relay sees EOF and the device goes:
/// nothing leaks when wraith has already gone away.
async fn send_created(stream: &mut UnixStream, node: &str, fd: &OwnedFd) {
    let reply = ControlEnvelope { msg: Some(ControlMsg::DeviceCreated(DeviceCreated { node: node.to_string() })) };
    if let Err(e) = send_frame_with_fd(stream, &reply, fd).await {
        warn!(node, error = %e, "devices: failed to hand the device socket to wraith");
    }
}

/// The socketpair between wraith and a device: SEQPACKET, so wraith's
/// write() of an event batch or a uhid event arrives as one packet and
/// its read() returns one uhid event, as they would on the device fd;
/// non-blocking at both ends, as wraith's event loop wants.
fn pair() -> Result<(OwnedFd, OwnedFd)> {
    let (ours, theirs) = socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
    )?;
    Ok((ours, theirs))
}

/// What a packet from wraith contains, after the checks below.
enum Packet {
    Data(usize),
    Closed,
}

/// For AsyncFd::try_io: EAGAIN comes back as a WouldBlock error, which
/// is what clears the fd's readiness. Returning it as a value would leave
/// readiness set and the relay loop spinning on `readable()`.
fn recv_packet(fd: &AsyncFd<OwnedFd>, buf: &mut [u8]) -> std::io::Result<Packet> {
    match recv(fd.as_raw_fd(), buf, MsgFlags::MSG_DONTWAIT) {
        Ok(0) => Ok(Packet::Closed),
        Ok(n) => Ok(Packet::Data(n)),
        Err(e) => Err(e.into()),
    }
}

/// wraith -> uinput: each packet is a batch of input_events, every one
/// of which must be something the pad was set up to report. A batch with
/// anything else is dropped whole and logged once.
async fn relay_gamepad(wraith: OwnedFd, device: OwnedFd, uid: u32, index: u32) {
    let wraith = match AsyncFd::new(wraith) {
        Ok(fd) => fd,
        Err(e) => {
            warn!(uid, index, error = %e, "devices: registering the gamepad socket failed");
            return;
        }
    };
    let mut buf = vec![0u8; MAX_BATCH * INPUT_EVENT_SIZE];
    let mut complained = false;
    loop {
        let mut guard = match wraith.readable().await {
            Ok(guard) => guard,
            Err(e) => {
                warn!(uid, index, error = %e, "devices: waiting on the gamepad socket failed");
                break;
            }
        };
        match guard.try_io(|fd| recv_packet(fd, &mut buf)) {
            Ok(Ok(Packet::Data(n))) => {
                if !valid_gamepad_batch(&buf[..n]) {
                    if !complained {
                        warn!(uid, index, len = n, "devices: dropping a gamepad event batch the pad can't report");
                        complained = true;
                    }
                    continue;
                }
                // EAGAIN (uinput's queue full) costs the batch, as it
                // would wraith writing the device directly.
                if let Err(e) = nix::unistd::write(&device, &buf[..n]) {
                    if e != nix::errno::Errno::EAGAIN {
                        warn!(uid, index, error = %e, "devices: writing to the gamepad failed");
                        break;
                    }
                }
            }
            Ok(Ok(Packet::Closed)) => break,
            Err(_would_block) => continue,
            Ok(Err(e)) => {
                warn!(uid, index, error = %e, "devices: reading the gamepad socket failed");
                break;
            }
        }
    }
    debug!(uid, index, "devices: gamepad closed");
    // `device` dropped here: UI_DEV_DESTROY.
}

/// True when `batch` is whole input_events, each an EV_SYN/SYN_REPORT, a
/// GAMEPAD_KEYS button with value 0 or 1, or a GAMEPAD_AXES axis within
/// its range.
fn valid_gamepad_batch(batch: &[u8]) -> bool {
    if batch.is_empty() || batch.len() % INPUT_EVENT_SIZE != 0 {
        return false;
    }
    batch.chunks_exact(INPUT_EVENT_SIZE).all(|chunk| {
        // Safety: input_event is plain data and the chunk is exactly its
        // size; read_unaligned makes no alignment assumption.
        let ev: libc::input_event = unsafe { std::ptr::read_unaligned(chunk.as_ptr() as *const libc::input_event) };
        match libc::c_int::from(ev.type_) {
            EV_SYN => ev.code == SYN_REPORT,
            EV_KEY => GAMEPAD_KEYS.contains(&libc::c_int::from(ev.code)) && (ev.value == 0 || ev.value == 1),
            EV_ABS => GAMEPAD_AXES.iter().any(|&(code, min, max, _, _)| code == ev.code && (min..=max).contains(&ev.value)),
            _ => false,
        }
    })
}

/// wraith <-> uhid, both ways: wraith's input reports and report replies
/// to the device, once each is checked, with UHID_INPUT2 held back until
/// `verified`; the driver's events (OUTPUT, GET_REPORT, SET_REPORT,
/// OPEN/CLOSE/START/STOP) to wraith, one packet each. For a security key
/// wraith may send only 64-byte input reports, and the relay fails the
/// driver's GET_REPORT and SET_REPORT itself instead of passing them on.
async fn relay_hid(wraith: OwnedFd, device: OwnedFd, verified: Arc<AtomicBool>, uid: u32, index: u32, kind: UhidKind) {
    let (wraith, device) = match (AsyncFd::new(wraith), AsyncFd::new(device)) {
        (Ok(w), Ok(d)) => (w, d),
        _ => {
            warn!(uid, index, "devices: registering the raw controller's fds failed");
            return;
        }
    };
    let mut from_wraith = vec![0u8; UHID_EVENT_SIZE];
    let mut from_device = vec![0u8; UHID_EVENT_SIZE];
    let mut complained = false;
    loop {
        tokio::select! {
            guard = wraith.readable() => {
                let Ok(mut guard) = guard else { break };
                match guard.try_io(|fd| recv_packet(fd, &mut from_wraith)) {
                    Ok(Ok(Packet::Data(n))) => {
                        let verified = verified.load(Ordering::Acquire);
                        let valid = match kind {
                            UhidKind::Controller => valid_uhid_from_wraith(&from_wraith[..n], verified),
                            UhidKind::SecurityKey => valid_key_uhid_from_wraith(&from_wraith[..n], verified),
                        };
                        if !valid {
                            if !complained {
                                warn!(uid, index, len = n, "devices: dropping a uhid event wraith may not send");
                                complained = true;
                            }
                            continue;
                        }
                        // EAGAIN: expected for a moment around a driver's
                        // (re)start; uhid takes input only while one is bound.
                        if let Err(e) = nix::unistd::write(&device, &from_wraith[..n]) {
                            if e != nix::errno::Errno::EAGAIN {
                                debug!(uid, index, error = %e, "devices: writing to the raw controller failed");
                                break;
                            }
                        }
                    }
                    Ok(Ok(Packet::Closed)) => break,
                    Err(_would_block) => continue,
                    Ok(Err(_)) => break,
                }
            }
            guard = device.readable() => {
                let Ok(mut guard) = guard else { break };
                let read = guard.try_io(|fd| nix::unistd::read(fd, &mut from_device).map_err(std::io::Error::from));
                match read {
                    Ok(Ok(0)) => break,
                    Ok(Ok(n)) => {
                        if kind == UhidKind::SecurityKey {
                            match key_driver_event(&from_device[..n]) {
                                KeyDriverEvent::Relay => {}
                                KeyDriverEvent::Drop => continue,
                                KeyDriverEvent::Answer(reply) => {
                                    if let Err(e) = nix::unistd::write(&device, &reply) {
                                        debug!(uid, index, error = %e, "devices: answering a security key's report request failed");
                                    }
                                    continue;
                                }
                            }
                        }
                        // A full socket costs the event; wraith reads
                        // promptly and the kernel resends what matters.
                        if let Err(e) = send(wraith.as_raw_fd(), &from_device[..n], MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL) {
                            if e != nix::errno::Errno::EAGAIN {
                                break;
                            }
                        }
                    }
                    Ok(Err(e)) => {
                        // UHID_DESTROY through the duplicate (a refused
                        // controller) lands here as an error.
                        debug!(uid, index, error = %e, "devices: reading the raw controller failed");
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }
    }
    debug!(uid, index, "devices: raw controller closed");
    // `device` dropped here: UHID_DESTROY.
}

/// Whether `ev` is a uhid event wraith may write: an input report (only
/// once the driver's verdict is in) or a reply to a driver request, no
/// longer than the kernel's struct, with a report size that fits.
fn valid_uhid_from_wraith(ev: &[u8], verified: bool) -> bool {
    if ev.len() < 4 || ev.len() > UHID_EVENT_SIZE {
        return false;
    }
    let ty = u32::from_ne_bytes(ev[..4].try_into().expect("4 bytes"));
    match ty {
        // uhid_input2_req: u16 size, data[UHID_DATA_MAX].
        UHID_INPUT2 => {
            if !verified || ev.len() < 6 {
                return false;
            }
            let size = u16::from_ne_bytes(ev[4..6].try_into().expect("2 bytes")) as usize;
            size <= HID_MAX_DESCRIPTOR_SIZE && 6 + size <= ev.len()
        }
        // uhid_get_report_reply_req: u32 id, u16 err, u16 size, data[].
        UHID_GET_REPORT_REPLY => {
            if ev.len() < 12 {
                return false;
            }
            let size = u16::from_ne_bytes(ev[10..12].try_into().expect("2 bytes")) as usize;
            size <= HID_MAX_DESCRIPTOR_SIZE && 12 + size <= ev.len()
        }
        // uhid_set_report_reply_req: u32 id, u16 err.
        UHID_SET_REPORT_REPLY => ev.len() >= 10,
        _ => false,
    }
}

/// Whether `ev` is a uhid event wraith may write for a security key: only
/// UHID_INPUT2 with one CTAPHID packet, once the driver's verdict is in.
/// wraith never answers a key's report requests; the relay does.
fn valid_key_uhid_from_wraith(ev: &[u8], verified: bool) -> bool {
    if !verified || ev.len() < 6 || ev.len() > UHID_EVENT_SIZE {
        return false;
    }
    let ty = u32::from_ne_bytes(ev[..4].try_into().expect("4 bytes"));
    let size = u16::from_ne_bytes(ev[4..6].try_into().expect("2 bytes")) as usize;
    ty == UHID_INPUT2 && size == FIDO_PACKET && 6 + size <= ev.len()
}

/// What the relay does with an event a security key's driver produced.
#[derive(Debug, PartialEq, Eq)]
enum KeyDriverEvent {
    /// Pass it to wraith: an output report, or the lifecycle events
    /// (START, STOP, OPEN, CLOSE) that carry no data.
    Relay,
    /// Fail it here: the reply for a GET_REPORT or SET_REPORT.
    Answer(Vec<u8>),
    Drop,
}

fn key_driver_event(ev: &[u8]) -> KeyDriverEvent {
    if ev.len() < 4 {
        return KeyDriverEvent::Drop;
    }
    let ty = u32::from_ne_bytes(ev[..4].try_into().expect("4 bytes"));
    match ty {
        UHID_OUTPUT | UHID_START | UHID_STOP | UHID_OPEN | UHID_CLOSE => KeyDriverEvent::Relay,
        // uhid_get_report_req / uhid_set_report_req both start with the
        // u32 id the reply (u32 id, u16 err, ...) must carry back.
        UHID_GET_REPORT | UHID_SET_REPORT if ev.len() >= 8 => {
            let reply_type = if ty == UHID_GET_REPORT { UHID_GET_REPORT_REPLY } else { UHID_SET_REPORT_REPLY };
            let mut reply = reply_type.to_ne_bytes().to_vec();
            reply.extend_from_slice(&ev[4..8]);
            reply.extend_from_slice(&(libc::EIO as u16).to_ne_bytes());
            if ty == UHID_GET_REPORT {
                reply.extend_from_slice(&0u16.to_ne_bytes()); // size
            }
            KeyDriverEvent::Answer(reply)
        }
        _ => KeyDriverEvent::Drop,
    }
}

// Everything the C side of a uinput setup does, in the order the kernel
// requires (bits and abs ranges before UI_DEV_SETUP, create last).
fn create_gamepad(phys: &str) -> Result<(OwnedFd, String)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(UINPUT_PATH)
        .with_context(|| format!("opening {UINPUT_PATH}"))?;
    let fd: OwnedFd = file.into();
    let raw = fd.as_raw_fd();

    // Safety, for every ioctl below: `raw` is the open uinput fd, and each
    // pointer argument is to a live local of the size the request encodes.
    check(unsafe { libc::ioctl(raw, UI_SET_EVBIT, EV_KEY) }, "UI_SET_EVBIT EV_KEY")?;
    check(unsafe { libc::ioctl(raw, UI_SET_EVBIT, EV_ABS) }, "UI_SET_EVBIT EV_ABS")?;
    for key in GAMEPAD_KEYS {
        check(unsafe { libc::ioctl(raw, UI_SET_KEYBIT, key) }, "UI_SET_KEYBIT")?;
    }
    for (code, min, max, fuzz, flat) in GAMEPAD_AXES {
        check(unsafe { libc::ioctl(raw, UI_SET_ABSBIT, code as libc::c_int) }, "UI_SET_ABSBIT")?;
        let mut setup: libc::uinput_abs_setup = unsafe { std::mem::zeroed() };
        setup.code = code;
        setup.absinfo.minimum = min;
        setup.absinfo.maximum = max;
        setup.absinfo.fuzz = fuzz;
        setup.absinfo.flat = flat;
        check(unsafe { libc::ioctl(raw, UI_ABS_SETUP, &setup) }, "UI_ABS_SETUP")?;
    }
    let phys_c = CString::new(phys).context("phys string")?;
    check(unsafe { libc::ioctl(raw, UI_SET_PHYS, phys_c.as_ptr()) }, "UI_SET_PHYS")?;

    let mut setup: libc::uinput_setup = unsafe { std::mem::zeroed() };
    setup.id.bustype = BUS_VIRTUAL;
    setup.id.vendor = VENDOR_ID;
    setup.id.product = PRODUCT_ID;
    setup.id.version = VERSION;
    for (dst, src) in setup.name.iter_mut().zip(DEVICE_NAME.bytes()) {
        *dst = src as libc::c_char;
    }
    check(unsafe { libc::ioctl(raw, UI_DEV_SETUP, &setup) }, "UI_DEV_SETUP")?;
    check(unsafe { libc::ioctl(raw, UI_DEV_CREATE) }, "UI_DEV_CREATE")?;

    let mut name = [0u8; SYSNAME_LEN];
    check(unsafe { libc::ioctl(raw, UI_GET_SYSNAME, name.as_mut_ptr()) }, "UI_GET_SYSNAME")?;
    let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
    let sysname = std::str::from_utf8(&name[..end]).context("sysname is not UTF-8")?.to_string();
    Ok((fd, sysname))
}

/// An ioctl's return value as a Result, errno attached.
fn check(ret: libc::c_int, what: &str) -> Result<()> {
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context(what.to_string());
    }
    Ok(())
}

/// Opens /dev/uhid and writes UHID_CREATE2. Non-blocking, as wraith's
/// event loop wants it (the flag belongs to the open file, which wraith
/// shares). Returns as soon as the kernel has queued the device; the
/// driver probes afterwards.
fn create_hid(name: &str, phys: &str, ident: &HidIdentity) -> Result<OwnedFd> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(UHID_PATH)
        .with_context(|| format!("opening {UHID_PATH}"))?;
    let fd: OwnedFd = file.into();
    write_uhid(&fd, &uhid_create2(name, phys, ident)).context("UHID_CREATE2")?;
    Ok(fd)
}

fn uhid_event(ty: u32) -> Vec<u8> {
    let mut ev = vec![0u8; UHID_EVENT_SIZE];
    ev[..4].copy_from_slice(&ty.to_ne_bytes());
    ev
}

// struct uhid_create2_req, packed: name[128] phys[64] uniq[64] rd_size:u16
// bus:u16 vendor:u32 product:u32 version:u32 country:u32 rd_data[4096].
fn uhid_create2(name: &str, phys: &str, ident: &HidIdentity) -> Vec<u8> {
    let mut ev = uhid_event(UHID_CREATE2);
    let mut at = 4;
    for (s, len) in [(name, UHID_NAME_LEN), (phys, UHID_PHYS_LEN), (ident.uniq.as_str(), UHID_UNIQ_LEN)] {
        let n = s.len().min(len - 1); // NUL-terminated
        ev[at..at + n].copy_from_slice(&s.as_bytes()[..n]);
        at += len;
    }
    let rd = &ident.report_descriptor;
    ev[at..at + 2].copy_from_slice(&(rd.len() as u16).to_ne_bytes());
    ev[at + 2..at + 4].copy_from_slice(&(ident.bus as u16).to_ne_bytes());
    ev[at + 4..at + 8].copy_from_slice(&ident.vendor_id.to_ne_bytes());
    ev[at + 8..at + 12].copy_from_slice(&ident.product_id.to_ne_bytes());
    ev[at + 12..at + 16].copy_from_slice(&ident.version.to_ne_bytes());
    // country (at + 16) stays 0: no platform reports it.
    at += 20;
    ev[at..at + rd.len()].copy_from_slice(rd);
    ev
}

fn write_uhid(fd: &OwnedFd, ev: &[u8]) -> Result<()> {
    let n = nix::unistd::write(fd, ev).map_err(std::io::Error::from)?;
    if n != ev.len() {
        bail!("short write to {UHID_PATH}: {n} of {}", ev.len());
    }
    Ok(())
}

/// What the driver made of a raw controller, once it has bound: the
/// driver must be on HID_DRIVERS, and every input device anywhere under
/// the HID device (drivers may hang child HID devices off it) must stay
/// within HID_EV_ALLOWED and HID_KEYS_ALLOWED.
fn verify_hid(devpath: &str, driver: &str) -> Result<()> {
    if !HID_DRIVERS.contains(&driver) {
        bail!("driver {driver:?} is not one ghost allows for a raw controller");
    }
    let mut inputs = Vec::new();
    find_input_devices(&Path::new("/sys").join(devpath.trim_start_matches('/')), &mut inputs);
    for input in &inputs {
        let caps = input.join("capabilities");
        let ev = read_bitmap(&caps.join("ev"))?;
        if let Some(bit) = first_bit_outside(&ev, |b| HID_EV_ALLOWED.contains(&b)) {
            bail!("{} reports event type {bit:#x}", input.display());
        }
        let keys = read_bitmap(&caps.join("key"))?;
        if let Some(bit) = first_bit_outside(&keys, |b| HID_KEYS_ALLOWED.iter().any(|r| r.contains(&b))) {
            bail!("{} reports key {bit:#x}", input.display());
        }
    }
    Ok(())
}

/// What the driver made of a security key: hid-generic, and no input
/// device anywhere under it -- FIDO_DESCRIPTOR has nothing to map, so one
/// would mean something other than the descriptor decided what it is.
fn verify_security_key(devpath: &str, driver: &str) -> Result<()> {
    if driver != SECURITY_KEY_DRIVER {
        bail!("driver {driver:?} bound to a security key (only {SECURITY_KEY_DRIVER} may)");
    }
    let mut inputs = Vec::new();
    find_input_devices(&Path::new("/sys").join(devpath.trim_start_matches('/')), &mut inputs);
    if let Some(input) = inputs.first() {
        bail!("the security key's driver made an input device, {}", input.display());
    }
    Ok(())
}

// Every input<N> directory below `dir`, not following symlinks (the
// `subsystem`, `driver` and `device` links point back up the tree).
fn find_input_devices(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_dir() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.strip_prefix("input").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())) {
            out.push(path.clone());
        }
        find_input_devices(&path, out);
    }
}

/// A sysfs capability bitmap: space-separated hex words of the kernel's
/// `unsigned long`, most significant first. Returned least significant
/// first.
fn read_bitmap(path: &Path) -> Result<Vec<u64>> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_bitmap(&text).with_context(|| format!("parsing {}", path.display()))
}

fn parse_bitmap(text: &str) -> Result<Vec<u64>> {
    text.split_whitespace().rev().map(|w| u64::from_str_radix(w, 16).context("not a hex word")).collect()
}

fn first_bit_outside(words: &[u64], allowed: impl Fn(usize) -> bool) -> Option<usize> {
    let width = size_of::<libc::c_ulong>() * 8;
    for (i, &word) in words.iter().enumerate() {
        for b in 0..width.min(64) {
            if word & (1u64 << b) != 0 && !allowed(i * width + b) {
                return Some(i * width + b);
            }
        }
    }
    None
}

/// Starts the udev monitor task for this session's uid. Call once,
/// inside the runtime, before any device is created; a failure leaves
/// gamepad forwarding disabled (available() and uhid_available() stay
/// false).
pub fn start_monitor(uid: u32) {
    OWNER_UID.store(uid, Ordering::Relaxed);
    match open_monitor() {
        Ok(fd) => {
            MONITOR_RUNNING.store(true, Ordering::Relaxed);
            tokio::spawn(async move {
                if let Err(e) = monitor_loop(fd).await {
                    warn!(error = %e, "devices: udev monitor stopped -- new devices won't be chowned");
                }
                MONITOR_RUNNING.store(false, Ordering::Relaxed);
                // Dropping the senders fails every pending verification.
                pending_binds().lock().unwrap().clear();
            });
        }
        Err(e) => warn!(error = %e, "devices: could not open the udev monitor"),
    }
}

// libudev's monitor protocol: netlink group 2 carries udevd's
// re-broadcast of each event after its rules ran (group 1 is the kernel's
// own, before them).
const UDEV_MONITOR_GROUP: u32 = 2;
const UDEV_MONITOR_MAGIC: u32 = 0xfeedcafe;

fn open_monitor() -> Result<AsyncFd<OwnedFd>> {
    let fd = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        SockProtocol::NetlinkKObjectUEvent,
    )
    .context("netlink socket")?;
    setsockopt(&fd, sockopt::PassCred, &true).context("SO_PASSCRED")?;
    // A burst of hotplug events (a dock, a hub) shouldn't cost ghost a
    // node: root can raise the buffer past rmem_max.
    let _ = setsockopt(&fd, sockopt::RcvBufForce, &(4 << 20));
    bind(fd.as_raw_fd(), &NetlinkAddr::new(0, UDEV_MONITOR_GROUP)).context("binding to udev's monitor group")?;
    AsyncFd::new(fd).context("registering the udev monitor")
}

async fn monitor_loop(fd: AsyncFd<OwnedFd>) -> Result<()> {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let mut guard = fd.readable().await.context("waiting on the udev monitor")?;
        let received = guard.try_io(|inner| {
            let mut iov = [IoSliceMut::new(&mut buf)];
            let mut cmsg = nix::cmsg_space!(UnixCredentials);
            let msg = recvmsg::<NetlinkAddr>(inner.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_DONTWAIT)
                .map_err(std::io::Error::from)?;
            let from_root = msg
                .cmsgs()
                .map(|mut c| c.any(|m| matches!(m, ControlMessageOwned::ScmCredentials(cr) if cr.uid() == 0)))
                .unwrap_or(false);
            Ok((msg.bytes, from_root))
        });
        let (len, from_root) = match received {
            Ok(Ok(r)) => r,
            Ok(Err(e)) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                warn!("devices: the udev monitor overflowed -- some device nodes may not have been chowned");
                continue;
            }
            Ok(Err(e)) => return Err(e).context("reading the udev monitor"),
            Err(_would_block) => continue,
        };
        if !from_root {
            continue;
        }
        if let Some(props) = parse_monitor_message(&buf[..len]) {
            handle_event(&props);
        }
    }
}

/// A libudev monitor message's properties, or None for anything else.
/// Layout (libudev's struct monitor_netlink_header): "libudev\0", magic
/// (big-endian), header_size, properties_off, properties_len, then hashes
/// and bloom filters this ignores; the properties are NUL-separated
/// KEY=VALUE strings at properties_off.
fn parse_monitor_message(msg: &[u8]) -> Option<HashMap<String, String>> {
    if msg.len() < 24 || &msg[..8] != b"libudev\0" {
        return None;
    }
    let u32_at = |at: usize| u32::from_ne_bytes(msg[at..at + 4].try_into().unwrap());
    if u32::from_be_bytes(msg[8..12].try_into().unwrap()) != UDEV_MONITOR_MAGIC {
        return None;
    }
    let off = u32_at(16) as usize;
    let len = u32_at(20) as usize;
    let props = msg.get(off..off.checked_add(len)?)?;
    Some(
        props
            .split(|&b| b == 0)
            .filter_map(|kv| std::str::from_utf8(kv).ok()?.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    )
}

fn handle_event(props: &HashMap<String, String>) {
    let get = |k: &str| props.get(k).map(String::as_str).unwrap_or("");
    let (action, subsystem, devpath) = (get("ACTION"), get("SUBSYSTEM"), get("DEVPATH"));
    if action == "bind" && subsystem == "hid" && get("HID_PHYS").starts_with(PHYS_PREFIX) {
        if let Some(tx) = pending_binds().lock().unwrap().remove(get("HID_PHYS")) {
            let _ = tx.send((devpath.to_string(), get("DRIVER").to_string()));
        }
        return;
    }
    // `change` too: udev re-applies a node's default owner and the rule's
    // mode on every change event (`udevadm trigger` after a package
    // install, say), which would take the node back from its session.
    if !(action == "add" || action == "change") || !(subsystem == "input" || subsystem == "hidraw") {
        return;
    }
    let node = get("DEVNAME");
    if node.is_empty() {
        return; // the input<N> device itself; its eventN/jsN follow
    }
    let Some(uid) = ghost_owner(&Path::new("/sys").join(devpath.trim_start_matches('/'))) else { return };
    if uid != OWNER_UID.load(Ordering::Relaxed) {
        return; // another session's device; its own ghostseat handles it
    }
    if get("ID_SEAT") != SEAT {
        warn!(node, uid, "devices: udev processed a ghost device without the seat rule -- it is visible to the console seat");
    }
    let chowned = nix::unistd::chown(node, Some(nix::unistd::Uid::from_raw(uid)), None)
        .map_err(anyhow::Error::from)
        .and_then(|()| Ok(std::fs::set_permissions(node, std::fs::Permissions::from_mode(0o600))?));
    match chowned {
        Ok(()) => debug!(node, uid, "devices: node handed to its session"),
        Err(e) => warn!(node, uid, error = %e, "devices: chowning a device node failed"),
    }
}

/// The uid a ghost device belongs to, from the nearest `phys` (a uinput
/// device's input<N>) or HID_PHYS (a uhid device) up the tree from
/// `syspath`: ghost/uid-<uid>/....
fn ghost_owner(syspath: &Path) -> Option<u32> {
    let mut dir = Some(syspath);
    while let Some(d) = dir {
        if !d.starts_with("/sys/devices") {
            return None;
        }
        if let Ok(phys) = std::fs::read_to_string(d.join("phys")) {
            if let Some(uid) = uid_from_phys(phys.trim()) {
                return Some(uid);
            }
        }
        if let Ok(uevent) = std::fs::read_to_string(d.join("uevent")) {
            if let Some(phys) = uevent.lines().find_map(|l| l.strip_prefix("HID_PHYS=")) {
                return uid_from_phys(phys);
            }
        }
        dir = d.parent();
    }
    None
}

fn uid_from_phys(phys: &str) -> Option<u32> {
    let rest = phys.strip_prefix(PHYS_PREFIX)?.strip_prefix("/uid-")?;
    rest.split('/').next()?.parse().ok()
}

/// One frame (gdp-spec.md §3.1 framing) with `fd` attached as
/// SCM_RIGHTS (wraith's end of a device's socketpair). The fd rides on
/// the first byte of the sendmsg, so the
/// whole frame goes in the one call; if the socket takes only part of
/// it, the rest follows as ordinary bytes -- the fd is already delivered.
async fn send_frame_with_fd(stream: &mut UnixStream, msg: &ControlEnvelope, fd: &OwnedFd) -> Result<()> {
    let frame = frame_bytes(msg)?;
    let raw_sock = stream.as_raw_fd();
    let fds = [fd.as_raw_fd()];
    let sent = stream
        .async_io(Interest::WRITABLE, || {
            sendmsg::<UnixAddr>(
                raw_sock,
                &[IoSlice::new(&frame)],
                &[ControlMessage::ScmRights(&fds)],
                MsgFlags::MSG_NOSIGNAL,
                None,
            )
            .map_err(std::io::Error::from)
        })
        .await
        .context("sendmsg with SCM_RIGHTS")?;
    if sent < frame.len() {
        stream.write_all(&frame[sent..]).await.context("writing the rest of the frame")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmaps_parse_most_significant_word_first() {
        let words = parse_bitmap("1 0\n").unwrap();
        assert_eq!(words, vec![0, 1]);
        assert_eq!(first_bit_outside(&words, |_| false), Some(64));
    }

    #[test]
    fn a_ps4_pads_input_devices_pass() {
        // A DS4 v2 under hid-playstation, as sysfs prints them: the
        // gamepad, the touchpad and the motion sensors.
        let allowed_ev = |b| HID_EV_ALLOWED.contains(&b);
        let allowed_key = |b| HID_KEYS_ALLOWED.iter().any(|r: &RangeInclusive<usize>| r.contains(&b));
        for (ev, key) in [
            ("20000b", "7fdb000000000000 0 0 0 0"),
            ("19", "0"),
            ("b", "2420 10000 0 0 0 0"),
        ] {
            assert_eq!(first_bit_outside(&parse_bitmap(ev).unwrap(), allowed_ev), None, "ev {ev}");
            assert_eq!(first_bit_outside(&parse_bitmap(key).unwrap(), allowed_key), None, "key {key}");
        }
    }

    #[test]
    fn keyboards_switches_and_pointers_fail() {
        let allowed_ev = |b| HID_EV_ALLOWED.contains(&b);
        let allowed_key = |b| HID_KEYS_ALLOWED.iter().any(|r: &RangeInclusive<usize>| r.contains(&b));
        // KEY_SYSRQ (99), KEY_POWER (116), KEY_POWER2 (0x164).
        for key in [99usize, 116, 0x164] {
            let mut words = vec![0u64; 12];
            words[key / 64] |= 1 << (key % 64);
            assert_eq!(first_bit_outside(&words, allowed_key), Some(key));
        }
        // EV_REL, EV_SW, EV_REP.
        for ev in [0x02usize, 0x05, 0x14] {
            assert_eq!(first_bit_outside(&[1u64 << ev], allowed_ev), Some(ev));
        }
    }

    #[test]
    fn uid_comes_from_ghost_phys_only() {
        assert_eq!(uid_from_phys("ghost/uid-1001/pad0"), Some(1001));
        assert_eq!(uid_from_phys("ghost/uid-1001/pad2/17"), Some(1001));
        assert_eq!(uid_from_phys("8a:88:4b:40:10:f2"), None);
        assert_eq!(uid_from_phys("ghostly/uid-1/pad0"), None);
    }

    #[test]
    fn create2_lays_out_like_the_kernel_struct() {
        let ident = HidIdentity {
            bus: BUS_BLUETOOTH,
            vendor_id: 0x054c,
            product_id: 0x09cc,
            version: 0x0100,
            uniq: "a4:ae:11:00:00:01".into(),
            report_descriptor: vec![0x05, 0x01, 0x09, 0x05],
        };
        let ev = uhid_create2("Wireless Controller", "ghost/uid-1/pad0/0", &ident);
        assert_eq!(ev.len(), UHID_EVENT_SIZE);
        assert_eq!(&ev[..4], &UHID_CREATE2.to_ne_bytes());
        assert_eq!(&ev[4..23], b"Wireless Controller");
        assert_eq!(&ev[132..150], b"ghost/uid-1/pad0/0");
        assert_eq!(&ev[196..213], b"a4:ae:11:00:00:01");
        assert_eq!(u16::from_ne_bytes([ev[260], ev[261]]), 4); // rd_size
        assert_eq!(u16::from_ne_bytes([ev[262], ev[263]]), 5); // bus
        assert_eq!(&ev[280..284], &[0x05, 0x01, 0x09, 0x05]); // rd_data
    }

    fn event(ty: u16, code: u16, value: i32) -> Vec<u8> {
        // Safety: input_event is plain data.
        let mut ev: libc::input_event = unsafe { std::mem::zeroed() };
        ev.type_ = ty;
        ev.code = code;
        ev.value = value;
        unsafe { std::slice::from_raw_parts(&ev as *const _ as *const u8, INPUT_EVENT_SIZE) }.to_vec()
    }

    #[test]
    fn gamepad_batches_are_checked_event_by_event() {
        let mut ok = event(EV_KEY as u16, 0x130, 1);
        ok.extend(event(EV_ABS as u16, 0x00, -32768));
        ok.extend(event(EV_ABS as u16, 0x10, 1));
        ok.extend(event(EV_SYN as u16, 0, 0));
        assert!(valid_gamepad_batch(&ok));
        // A keyboard key, a key value past 1, an axis out of range, EV_REL,
        // a short batch, an empty one.
        assert!(!valid_gamepad_batch(&event(EV_KEY as u16, 99, 1)));
        assert!(!valid_gamepad_batch(&event(EV_KEY as u16, 0x130, 2)));
        assert!(!valid_gamepad_batch(&event(EV_ABS as u16, 0x02, 256)));
        assert!(!valid_gamepad_batch(&event(0x02, 0, 1)));
        assert!(!valid_gamepad_batch(&ok[..INPUT_EVENT_SIZE + 1]));
        assert!(!valid_gamepad_batch(&[]));
    }

    #[test]
    fn uhid_events_from_wraith_are_checked() {
        let mut input2 = UHID_INPUT2.to_ne_bytes().to_vec();
        input2.extend(8u16.to_ne_bytes());
        input2.extend([0u8; 8]);
        assert!(valid_uhid_from_wraith(&input2, true));
        assert!(!valid_uhid_from_wraith(&input2, false)); // before the verdict
        let mut short = input2.clone();
        short.truncate(10); // claims 8 data bytes, carries 4
        assert!(!valid_uhid_from_wraith(&short, true));
        let mut get_reply = UHID_GET_REPORT_REPLY.to_ne_bytes().to_vec();
        get_reply.extend([0u8; 8]); // id, err, size 0
        assert!(valid_uhid_from_wraith(&get_reply, false));
        let mut set_reply = UHID_SET_REPORT_REPLY.to_ne_bytes().to_vec();
        set_reply.extend([0u8; 6]);
        assert!(valid_uhid_from_wraith(&set_reply, false));
        assert!(!valid_uhid_from_wraith(&uhid_event(UHID_DESTROY), true));
        assert!(!valid_uhid_from_wraith(&uhid_event(UHID_CREATE2), true));
        assert!(!valid_uhid_from_wraith(&[0u8; 3], true));
        assert!(!valid_uhid_from_wraith(&vec![0u8; UHID_EVENT_SIZE + 1], true));
    }

    // The relays, with socketpairs standing in for the device.

    async fn recv_within(fd: &AsyncFd<OwnedFd>) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; UHID_EVENT_SIZE];
        let read = async {
            loop {
                let mut guard = fd.readable().await.unwrap();
                match guard.try_io(|fd| recv_packet(fd, &mut buf)) {
                    Ok(Ok(Packet::Data(n))) => return Some(buf[..n].to_vec()),
                    Ok(Ok(Packet::Closed)) => return None,
                    Err(_would_block) => continue,
                    Ok(Err(e)) => panic!("recv: {e}"),
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(2), read).await.expect("no packet within 2 s")
    }

    fn send_packet(fd: &AsyncFd<OwnedFd>, data: &[u8]) {
        assert_eq!(send(fd.as_raw_fd(), data, MsgFlags::MSG_NOSIGNAL).unwrap(), data.len());
    }

    fn async_pair() -> (OwnedFd, AsyncFd<OwnedFd>) {
        let (relay_end, test_end) = pair().unwrap();
        (relay_end, AsyncFd::new(test_end).unwrap())
    }

    #[tokio::test]
    async fn gamepad_relay_passes_checked_batches_and_destroys_on_close() {
        let (wraith_relay, wraith) = async_pair();
        let (device_relay, device) = async_pair();
        let relay = tokio::spawn(relay_gamepad(wraith_relay, device_relay, 1000, 0));

        let mut ok = event(EV_KEY as u16, 0x130, 1);
        ok.extend(event(EV_SYN as u16, 0, 0));
        let mut bad = event(EV_KEY as u16, 99, 1); // KEY_SYSRQ
        bad.extend(event(EV_SYN as u16, 0, 0));
        send_packet(&wraith, &bad);
        send_packet(&wraith, &ok);
        // The bad batch never reaches the device; the next packet it sees
        // is the good one, byte for byte.
        assert_eq!(recv_within(&device).await, Some(ok));

        // wraith closing its end ends the relay, which drops the device fd
        // (UI_DEV_DESTROY on the real thing): the device end reads EOF.
        drop(wraith);
        assert_eq!(recv_within(&device).await, None);
        relay.await.unwrap();
    }

    #[tokio::test]
    async fn hid_relay_holds_input_until_verified_and_passes_the_driver_back() {
        let (wraith_relay, wraith) = async_pair();
        let (device_relay, device) = async_pair();
        let verified = Arc::new(AtomicBool::new(false));
        let relay = tokio::spawn(relay_hid(wraith_relay, device_relay, verified.clone(), 1000, 0, UhidKind::Controller));

        let mut input2 = UHID_INPUT2.to_ne_bytes().to_vec();
        input2.extend(8u16.to_ne_bytes());
        input2.extend([0u8; 8]);
        let mut get_reply = UHID_GET_REPORT_REPLY.to_ne_bytes().to_vec();
        get_reply.extend([0u8; 8]);
        // Before the verdict: the input report is dropped, the reply to the
        // driver's request goes through.
        send_packet(&wraith, &input2);
        send_packet(&wraith, &get_reply);
        assert_eq!(recv_within(&device).await, Some(get_reply));
        // After it, input flows.
        verified.store(true, Ordering::Release);
        send_packet(&wraith, &input2);
        assert_eq!(recv_within(&device).await, Some(input2));

        // The driver's events come back whole, one packet each.
        let output = uhid_event(6); // UHID_OUTPUT
        send_packet(&device, &output);
        assert_eq!(recv_within(&wraith).await, Some(output));

        // The device going away (UHID_DESTROY through ghostseat's duplicate,
        // here the stand-in closing) ends the relay and wraith's end.
        drop(device);
        assert_eq!(recv_within(&wraith).await, None);
        relay.await.unwrap();
    }

    fn key_input2(size: u16, carried: usize) -> Vec<u8> {
        let mut ev = UHID_INPUT2.to_ne_bytes().to_vec();
        ev.extend(size.to_ne_bytes());
        ev.extend(vec![0xaau8; carried]);
        ev
    }

    #[tokio::test]
    async fn key_relay_passes_packets_and_fails_report_requests_itself() {
        let (wraith_relay, wraith) = async_pair();
        let (device_relay, device) = async_pair();
        // Verified from the start: holding input back before the verdict is
        // key_events_from_wraith_are_whole_packets_only's.
        let verified = Arc::new(AtomicBool::new(true));
        let relay = tokio::spawn(relay_hid(wraith_relay, device_relay, verified, 1000, 0, UhidKind::SecurityKey));

        // Only a whole packet goes through: not a reply to a report request,
        // not a short report.
        let packet = key_input2(64, 64);
        let mut get_reply = UHID_GET_REPORT_REPLY.to_ne_bytes().to_vec();
        get_reply.extend([0u8; 8]);
        send_packet(&wraith, &get_reply);
        send_packet(&wraith, &key_input2(8, 8));
        send_packet(&wraith, &packet);
        assert_eq!(recv_within(&device).await, Some(packet));

        // The driver's GET_REPORT is failed by the relay, toward the device,
        // and never reaches wraith; its output report does.
        let mut get_report = UHID_GET_REPORT.to_ne_bytes().to_vec();
        get_report.extend(7u32.to_ne_bytes());
        get_report.extend([0u8, 0]); // rnum, rtype
        send_packet(&device, &get_report);
        let mut failed = UHID_GET_REPORT_REPLY.to_ne_bytes().to_vec();
        failed.extend(7u32.to_ne_bytes());
        failed.extend((libc::EIO as u16).to_ne_bytes());
        failed.extend(0u16.to_ne_bytes());
        assert_eq!(recv_within(&device).await, Some(failed));
        let output = uhid_event(UHID_OUTPUT);
        send_packet(&device, &output);
        assert_eq!(recv_within(&wraith).await, Some(output));

        drop(wraith);
        assert_eq!(recv_within(&device).await, None);
        relay.await.unwrap();
    }

    #[test]
    fn key_events_from_wraith_are_whole_packets_only() {
        assert!(valid_key_uhid_from_wraith(&key_input2(64, 64), true));
        assert!(!valid_key_uhid_from_wraith(&key_input2(64, 64), false));
        assert!(!valid_key_uhid_from_wraith(&key_input2(65, 65), true));
        assert!(!valid_key_uhid_from_wraith(&key_input2(64, 10), true));
        let mut set_reply = UHID_SET_REPORT_REPLY.to_ne_bytes().to_vec();
        set_reply.extend([0u8; 6]);
        assert!(!valid_key_uhid_from_wraith(&set_reply, true));
        assert!(!valid_key_uhid_from_wraith(&uhid_event(UHID_CREATE2), true));
    }

    #[test]
    fn key_driver_events_are_relayed_answered_or_dropped() {
        assert_eq!(key_driver_event(&uhid_event(UHID_OUTPUT)), KeyDriverEvent::Relay);
        assert_eq!(key_driver_event(&uhid_event(UHID_OPEN)), KeyDriverEvent::Relay);
        let mut set_report = UHID_SET_REPORT.to_ne_bytes().to_vec();
        set_report.extend(9u32.to_ne_bytes());
        set_report.extend([0u8; 4]);
        let mut failed = UHID_SET_REPORT_REPLY.to_ne_bytes().to_vec();
        failed.extend(9u32.to_ne_bytes());
        failed.extend((libc::EIO as u16).to_ne_bytes());
        assert_eq!(key_driver_event(&set_report), KeyDriverEvent::Answer(failed));
        assert_eq!(key_driver_event(&uhid_event(UHID_DESTROY)), KeyDriverEvent::Drop);
        assert_eq!(key_driver_event(&[0u8; 2]), KeyDriverEvent::Drop);
    }

    #[test]
    fn a_key_gets_ghostseats_descriptor_and_only_the_clients_ids() {
        let sent = HidIdentity { vendor_id: 0x1050, product_id: 0x0407, version: 0x0543, ..Default::default() };
        let ident = security_key_identity("YubiKey OTP+FIDO+CCID", &sent).unwrap();
        assert_eq!(ident.bus, BUS_USB);
        assert_eq!(ident.report_descriptor, FIDO_DESCRIPTOR);
        assert_eq!((ident.vendor_id, ident.product_id, ident.version), (0x1050, 0x0407, 0x0543));
        // The fixed descriptor passes the screen check_identity runs too.
        screen_descriptor(&FIDO_DESCRIPTOR).unwrap();
        // A descriptor, a serial or a bus from wraith is refused.
        for bad in [
            HidIdentity { report_descriptor: vec![0x05, 0x01], ..sent.clone() },
            HidIdentity { uniq: "123456".into(), ..sent.clone() },
            HidIdentity { bus: BUS_BLUETOOTH, ..sent.clone() },
            HidIdentity { vendor_id: 0x1_0000, ..sent.clone() },
        ] {
            assert!(security_key_identity("YubiKey", &bad).is_err());
        }
    }

    #[test]
    fn the_fido_descriptor_is_the_specs() {
        // gdp-spec.md §8.7, byte for byte.
        let spec: &[u8] = &[
            0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01, 0x09, 0x20, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40,
            0x81, 0x02, 0x09, 0x21, 0x15, 0x00, 0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x40, 0x91, 0x02, 0xc0,
        ];
        assert_eq!(&FIDO_DESCRIPTOR[..], spec);
    }

    #[test]
    fn a_security_key_must_be_hid_generic_with_no_input_device() {
        // No such devpath: no input devices are found under it.
        verify_security_key("/devices/virtual/misc/uhid/0003:1050:0407.ffff", "hid-generic").unwrap();
        assert!(verify_security_key("/devices/virtual/misc/uhid/0003:1050:0407.ffff", "steam").is_err());
    }

    /// handle_create for a security key against the real kernel, with this
    /// test as wraith and a real key at `GHOST_TEST_KEY` (its FIDO hidraw
    /// node) behind the device: the driver's verdict, the node handed to
    /// `GHOST_TEST_UID`, and a CTAPHID_INIT and CTAP2 GetInfo through the
    /// virtual node answered by the key. Needs root, /dev/uhid and the
    /// installed udev rule. Build as yourself and run the binary as root,
    /// so no root-owned files land in target/:
    ///   cargo test -p ghostseat --no-run
    ///   sudo GHOST_TEST_KEY=/dev/hidrawN GHOST_TEST_UID=$(id -u) \
    ///     target/debug/deps/ghostseat-... --ignored --nocapture real_security_key
    /// GHOST_TEST_HOLD=<seconds> keeps the bridge up afterwards, to try the
    /// virtual key from a browser.
    #[tokio::test]
    #[ignore = "needs root, /dev/uhid, the udev rule and a real key (GHOST_TEST_KEY)"]
    async fn real_security_key_through_ghostseat() {
        use std::io::{Read, Write};
        use std::os::unix::fs::MetadataExt;

        let key_path = std::env::var("GHOST_TEST_KEY").expect("GHOST_TEST_KEY=/dev/hidrawN, the key's FIDO interface");
        let uid: u32 = std::env::var("GHOST_TEST_UID").expect("GHOST_TEST_UID").parse().unwrap();
        start_monitor(uid);
        assert!(uhid_available(), "uhid, the udev rule or the monitor is missing");

        // ghostseat's end of the control connection, and ours as wraith.
        let (seat, mut wraith) = UnixStream::pair().unwrap();
        let req = CreateDevice {
            kind: create_device::Kind::SecurityKey as i32,
            index: 0,
            name: "Ghost test security key".into(),
            hid: Some(HidIdentity { vendor_id: 0x1050, product_id: 0x0407, version: 0x0100, ..Default::default() }),
        };
        tokio::spawn(handle_create(seat, uid, "test".into(), req));

        // DeviceCreated, with the relay socket as SCM_RIGHTS.
        let (frame, relay) = wraith
            .async_io(Interest::READABLE, || {
                let mut buf = vec![0u8; 4096];
                let mut iov = [IoSliceMut::new(&mut buf)];
                let mut cmsg = nix::cmsg_space!([std::os::fd::RawFd; 1]);
                let msg = recvmsg::<UnixAddr>(wraith.as_raw_fd(), &mut iov, Some(&mut cmsg), MsgFlags::MSG_DONTWAIT)
                    .map_err(std::io::Error::from)?;
                let fd = msg.cmsgs().unwrap().find_map(|c| match c {
                    ControlMessageOwned::ScmRights(fds) => fds.first().copied(),
                    _ => None,
                });
                let n = msg.bytes;
                Ok((buf[..n].to_vec(), fd))
            })
            .await
            .unwrap();
        let created: ControlEnvelope = ipc::framing::read_frame_sync(&mut std::io::Cursor::new(frame), 4096).unwrap();
        assert!(matches!(created.msg, Some(ControlMsg::DeviceCreated(_))), "{created:?}");
        // Safety: the fd just arrived over SCM_RIGHTS and nothing else owns it.
        let relay: OwnedFd = unsafe { std::os::fd::FromRawFd::from_raw_fd(relay.expect("no fd with DeviceCreated")) };

        // Bridge the relay to the real key before the verdict, as wraith
        // answers a driver's probe (a key's needs nothing, but the order is
        // wraith's). Input reports are dropped until the verdict.
        let relay = Arc::new(relay);
        let key = Arc::new(std::fs::OpenOptions::new().read(true).write(true).open(&key_path).unwrap());
        {
            let (relay, key) = (relay.clone(), key.clone());
            std::thread::spawn(move || loop {
                let mut packet = [0u8; FIDO_PACKET];
                let n = (&*key).read(&mut packet).unwrap();
                let mut ev = UHID_INPUT2.to_ne_bytes().to_vec();
                ev.extend((n as u16).to_ne_bytes());
                ev.extend(&packet[..n]);
                let _ = send(relay.as_raw_fd(), &ev, MsgFlags::MSG_NOSIGNAL);
            });
        }
        {
            let (relay, key) = (relay.clone(), key.clone());
            std::thread::spawn(move || {
                let mut ev = vec![0u8; UHID_EVENT_SIZE];
                loop {
                    let n = match recv(relay.as_raw_fd(), &mut ev, MsgFlags::MSG_DONTWAIT) {
                        Ok(0) => return,
                        Ok(n) => n,
                        Err(nix::errno::Errno::EAGAIN) => {
                            std::thread::sleep(Duration::from_millis(1));
                            continue;
                        }
                        Err(e) => panic!("relay recv: {e}"),
                    };
                    let ty = u32::from_ne_bytes(ev[..4].try_into().unwrap());
                    eprintln!("bridge: uhid event {ty} ({n} bytes)");
                    if ty == UHID_OUTPUT {
                        // uhid_output_req: data[4096], u16 size, u8 rtype.
                        let size = u16::from_ne_bytes(ev[4 + 4096..4 + 4098].try_into().unwrap()) as usize;
                        // The report ID (0, unnumbered) leads, as hidraw wants it.
                        (&*key).write_all(&ev[4..4 + size]).unwrap();
                    }
                }
            });
        }

        let verified: ControlEnvelope = ipc::framing::read_frame(&mut wraith).await.unwrap();
        let Some(ControlMsg::DeviceVerified(v)) = verified.msg else { panic!("not verified: {verified:?}") };
        assert_eq!(v.driver, "hid-generic");

        // The virtual key's hidraw node, once udev and the monitor are done.
        let mut node = None;
        for _ in 0..300 {
            node = std::fs::read_dir("/sys/class/hidraw").unwrap().flatten().find_map(|e| {
                let uevent = std::fs::read_to_string(e.path().join("device/uevent")).ok()?;
                uevent
                    .contains(&format!("HID_PHYS={PHYS_PREFIX}/uid-{uid}/key0/"))
                    .then(|| PathBuf::from("/dev").join(e.file_name()))
            });
            if node.as_ref().is_some_and(|n| std::fs::metadata(n).is_ok_and(|m| m.uid() == uid)) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let node = node.expect("no hidraw node for the key");
        let meta = std::fs::metadata(&node).unwrap();
        eprintln!("virtual key: {} uid {} mode {:o}", node.display(), meta.uid(), meta.mode() & 0o777);
        assert_eq!(meta.uid(), uid, "the node wasn't handed to the session's uid");
        assert_eq!(meta.mode() & 0o777, 0o600);

        // CTAPHID_INIT on the broadcast channel, then CTAP2 GetInfo on the
        // channel it allocates, through the virtual node. Blocking reads,
        // off the runtime's one thread, which the relay task needs.
        tokio::task::spawn_blocking(move || {
            let mut dev = std::fs::OpenOptions::new().read(true).write(true).open(&node).unwrap();
            let write_packet = |dev: &mut std::fs::File, cid: [u8; 4], cmd: u8, payload: &[u8]| {
                let mut report = vec![0u8; 1 + FIDO_PACKET]; // report ID 0 first
                report[1..5].copy_from_slice(&cid);
                report[5] = cmd;
                report[6..8].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                report[8..8 + payload.len()].copy_from_slice(payload);
                dev.write_all(&report).unwrap();
            };
            let nonce = [1u8, 2, 3, 4, 5, 6, 7, 8];
            write_packet(&mut dev, [0xff; 4], 0x86, &nonce);
            let mut packet = [0u8; FIDO_PACKET];
            assert_eq!(dev.read(&mut packet).unwrap(), FIDO_PACKET);
            assert_eq!(packet[4], 0x86, "not an INIT reply: {packet:02x?}");
            assert_eq!(&packet[7..15], &nonce);
            let cid: [u8; 4] = packet[15..19].try_into().unwrap();
            eprintln!("CTAPHID_INIT: channel {cid:02x?}, CTAPHID {} firmware {}.{}.{}", packet[19], packet[20], packet[21], packet[22]);

            write_packet(&mut dev, cid, 0x90, &[0x04]); // CTAPHID_CBOR, authenticatorGetInfo
            let mut reply = Vec::new();
            let mut total = None;
            while total.is_none_or(|t| reply.len() < t) {
                assert_eq!(dev.read(&mut packet).unwrap(), FIDO_PACKET);
                assert_eq!(&packet[..4], &cid);
                match total {
                    None if packet[4] == 0xbb => continue, // keep-alive
                    None => {
                        assert_eq!(packet[4], 0x90, "not a CBOR reply: {packet:02x?}");
                        let t = u16::from_be_bytes([packet[5], packet[6]]) as usize;
                        total = Some(t);
                        reply.extend(&packet[7..7 + t.min(57)]);
                    }
                    Some(t) => reply.extend(&packet[5..5 + (t - reply.len()).min(59)]),
                }
            }
            assert_eq!(reply[0], 0, "GetInfo failed with CTAP status {:#x}", reply[0]);
            let text = String::from_utf8_lossy(&reply);
            eprintln!("GetInfo: {} bytes, FIDO_2_0 {}, U2F_V2 {}", reply.len(), text.contains("FIDO_2_0"), text.contains("U2F_V2"));
            assert!(text.contains("FIDO_2_0"));
        })
        .await
        .unwrap();

        if let Some(secs) = std::env::var("GHOST_TEST_HOLD").ok().and_then(|s| s.parse().ok()) {
            eprintln!("holding the bridge for {secs} s");
            tokio::time::sleep(Duration::from_secs(secs)).await;
        }
    }

    #[tokio::test]
    async fn a_second_claim_on_a_slot_cancels_and_outlives_the_first() {
        let (first, mut first_cancelled) = claim_slot(create_device::Kind::Gamepad, 3).await;
        assert!(first_cancelled.try_recv().is_err());
        // The second claim cancels the first and waits for it to end, so it
        // can't complete while `first` is still held.
        let second = tokio::spawn(claim_slot(create_device::Kind::Gamepad, 3));
        tokio::time::timeout(Duration::from_millis(200), &mut first_cancelled)
            .await
            .expect("the first claim is cancelled")
            .unwrap_err();
        tokio::task::yield_now().await;
        assert!(!second.is_finished());
        drop(first);
        let (_second, _) = tokio::time::timeout(Duration::from_secs(2), second).await.unwrap().unwrap();
        // Other slots and the other kind are untouched.
        let (_other, mut other_cancelled) = claim_slot(create_device::Kind::Hid, 3).await;
        assert!(other_cancelled.try_recv().is_err());
        let (_key, mut key_cancelled) = claim_slot(create_device::Kind::SecurityKey, 1).await;
        assert!(key_cancelled.try_recv().is_err());
    }

    // The descriptor screen.

    // The gamepad collection a DualShock 4 starts with: axes, hat, 14
    // buttons, a vendor-page counter, the triggers.
    const DS4_GAMEPAD: &[u8] = &[
        0x05, 0x01, 0x09, 0x05, 0xa1, 0x01, 0x85, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x32, 0x09, 0x35, 0x15, 0x00,
        0x26, 0xff, 0x00, 0x75, 0x08, 0x95, 0x04, 0x81, 0x02, 0x09, 0x39, 0x15, 0x00, 0x25, 0x07, 0x35, 0x00, 0x46,
        0x3b, 0x01, 0x65, 0x14, 0x75, 0x04, 0x95, 0x01, 0x81, 0x42, 0x65, 0x00, 0x05, 0x09, 0x19, 0x01, 0x29, 0x0e,
        0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x0e, 0x81, 0x02, 0x06, 0x00, 0xff, 0x09, 0x20, 0x75, 0x06, 0x95,
        0x01, 0x15, 0x00, 0x25, 0x7f, 0x81, 0x02, 0x05, 0x01, 0x09, 0x33, 0x09, 0x34, 0x15, 0x00, 0x26, 0xff, 0x00,
        0x75, 0x08, 0x95, 0x02, 0x81, 0x02, 0xc0,
    ];

    #[test]
    fn a_gamepad_descriptor_passes_the_screen() {
        screen_descriptor(DS4_GAMEPAD).unwrap();
        // A joystick with a Physical Interface (rumble) collection and a
        // 4-byte vendor usage.
        let joystick: &[u8] = &[
            0x05, 0x01, 0x09, 0x04, 0xa1, 0x01, 0x05, 0x0f, 0x09, 0x21, 0xa1, 0x02, 0x0b, 0x01, 0x00, 0x00, 0xff, 0x91,
            0x02, 0xc0, 0xc0,
        ];
        screen_descriptor(joystick).unwrap();
    }

    #[test]
    fn keyboards_consumer_and_system_control_fail_the_screen() {
        // A boot keyboard: Generic Desktop Keyboard collection, Keyboard page keys.
        let keyboard: &[u8] = &[
            0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25, 0x01, 0x75, 0x01,
            0x95, 0x08, 0x81, 0x02, 0xc0,
        ];
        assert!(screen_descriptor(keyboard).unwrap_err().to_string().contains("application collection"));
        // Keyboard keys hidden inside a gamepad collection.
        let mut sneaky = DS4_GAMEPAD[..DS4_GAMEPAD.len() - 1].to_vec();
        sneaky.extend([0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0xc0]);
        assert!(screen_descriptor(&sneaky).unwrap_err().to_string().contains("Keyboard"));
        // The same key range as a 4-byte usage with the page in the high half.
        let mut extended = DS4_GAMEPAD[..DS4_GAMEPAD.len() - 1].to_vec();
        extended.extend([0x1b, 0xe0, 0x00, 0x07, 0x00, 0x2b, 0xe7, 0x00, 0x07, 0x00, 0x81, 0x02, 0xc0]);
        assert!(screen_descriptor(&extended).unwrap_err().to_string().contains("Keyboard"));
        // Consumer Control (media keys) and System Control (power, sleep).
        let consumer: &[u8] = &[0x05, 0x0c, 0x09, 0x01, 0xa1, 0x01, 0x19, 0x00, 0x2a, 0x3c, 0x02, 0x81, 0x00, 0xc0];
        assert!(screen_descriptor(consumer).unwrap_err().to_string().contains("Consumer"));
        let system: &[u8] = &[0x05, 0x01, 0x09, 0x80, 0xa1, 0x01, 0x19, 0x81, 0x29, 0x83, 0x81, 0x02, 0xc0];
        assert!(screen_descriptor(system).unwrap_err().to_string().contains("System Control"));
        let mouse: &[u8] = &[0x05, 0x01, 0x09, 0x02, 0xa1, 0x01, 0x09, 0x01, 0xa1, 0x00, 0xc0, 0xc0];
        assert!(screen_descriptor(mouse).is_err());
    }

    #[test]
    fn malformed_descriptors_fail_the_screen() {
        assert!(screen_descriptor(&[0xfe, 0x01, 0x00, 0x00]).unwrap_err().to_string().contains("long item"));
        assert!(screen_descriptor(&[0x05, 0x01, 0x09]).unwrap_err().to_string().contains("past the end"));
        assert!(screen_descriptor(&[0x07, 0x01, 0x00]).unwrap_err().to_string().contains("past the end"));
    }

    #[test]
    fn monitor_messages_parse() {
        let props = b"ACTION=add\0SUBSYSTEM=hidraw\0DEVNAME=/dev/hidraw1\0";
        let mut msg = Vec::new();
        msg.extend_from_slice(b"libudev\0");
        msg.extend_from_slice(&UDEV_MONITOR_MAGIC.to_be_bytes());
        msg.extend_from_slice(&40u32.to_ne_bytes()); // header_size
        msg.extend_from_slice(&40u32.to_ne_bytes()); // properties_off
        msg.extend_from_slice(&(props.len() as u32).to_ne_bytes());
        msg.resize(40, 0);
        msg.extend_from_slice(props);
        let p = parse_monitor_message(&msg).unwrap();
        assert_eq!(p["DEVNAME"], "/dev/hidraw1");
        assert_eq!(p["SUBSYSTEM"], "hidraw");
        assert!(parse_monitor_message(b"add@/devices/virtual/misc/uhid\0ACTION=add\0").is_none());
    }
}
