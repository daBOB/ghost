// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// Wisp thin clients (docs/design/wisp.md, gdp-spec.md §14).
// Every Wisp client's wisp-agent keeps one connection to Veil's lobby port
// (ALPN `wisp/1`) while it is up: a WispHello with the boot server's shared
// key and the client's report, then session changes as they happen. Veil
// answers with the profile the client applies -- the defaults, with any of
// the client's own settings in their place -- pushes a new one whenever an
// administrator saves either, and passes on an administrator's log out,
// restart or shut down. The connection is the client's
// online state; the database keeps the last report, so offline clients
// stay listed with their names.
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use ipc::framing::{read_frame_max, write_frame, FrameError};
use ipc::lobby::LobbyErrorCode;
use ipc::wisp::{
    wisp_envelope::Msg, ClientProfile, WispAction, WispCommand, WispEnvelope, WispHello, WispProfile, WispWelcome,
};
use preauth::{Offense, StartupSlot};
use quinn::VarInt;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::{timeout_at, Instant};
use tracing::{debug, info, warn};

use crate::db::{constant_time_eq, Db, ThinClientRow};
use crate::Veil;

// A hello is a few short lists; anything after it smaller still.
const MAX_FRAME: u32 = 16 * 1024;
// The settings row the profile lives in.
const PROFILE_KEY: &str = "thin_client_profile";

/// The settings a thin client applies: spectre's, at its next spectre
/// launch (SpectreSettings, client/spectre-settings/spectre_settings.h,
/// minus what Wisp always does), and the client's own, at once. The
/// defaults are stored as JSON in `settings`; a client's own settings
/// override some of their fields (Overrides).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    /// "WIDTHxHEIGHT"; empty: each client's own screen.
    pub resolution: String,
    /// "fit", "actual", or empty: whatever spectre's menu last picked.
    pub view: String,
    /// "vulkan", "native" or "software".
    pub preferred_decoder: String,
    /// A gdp/video_codec.hpp token, or empty: auto.
    pub preferred_codec: String,
    /// Start sessions lossless; false passes spectre -R off. The session
    /// menu's Lossless Refinement row switches it either way.
    pub lossless_refinement: bool,
    pub allow_pyrowave: bool,
    /// "auto", "lan", "internet" or "mobile".
    pub network_profile: String,
    pub forward_gamepads: bool,
    /// Forward the client's FIDO security keys to the host (spectre -U).
    /// Off by default: a forwarded key signs whatever the session asks,
    /// once the user touches it.
    pub forward_security_keys: bool,
    /// Send the client's microphone to the host (spectre -M).
    pub microphone: bool,
    /// Run spectre with SPECTRE_LOG=debug.
    pub debug_logging: bool,
    /// Turn the display off after this many minutes without input; 0:
    /// never.
    pub display_sleep_minutes: u32,
    /// "display", "builtin" or "auto" (AUDIO_OUTPUTS).
    pub audio_output: String,
}

/// The Profile fields one client sets for itself, by their JSON names; the
/// rest are the defaults'.
pub type Overrides = serde_json::Map<String, serde_json::Value>;

/// SpectreSettings' own defaults.
impl Default for Profile {
    fn default() -> Self {
        Profile {
            resolution: String::new(),
            view: String::new(),
            preferred_decoder: "vulkan".into(),
            preferred_codec: String::new(),
            lossless_refinement: true,
            allow_pyrowave: true,
            network_profile: "auto".into(),
            forward_gamepads: true,
            forward_security_keys: false,
            microphone: false,
            debug_logging: false,
            display_sleep_minutes: 20,
            audio_output: "display".into(),
        }
    }
}

pub const VIEWS: &[&str] = &["", "fit", "actual"];
pub const DECODERS: &[&str] = &["vulkan", "native", "software"];
/// gdp::all_video_codec_tokens() (libgdp/src/video_codec.cpp), and auto.
pub const CODECS: &[&str] = &["", "pyrowave", "av1", "h265", "h264"];
pub const NETWORK_PROFILES: &[&str] = &["auto", "lan", "internet", "mobile"];
/// The monitor's HDMI/DisplayPort audio, the speaker or audio jack, or
/// WirePlumber's own choice (client/wisp/image's wisp/audio-output.lua).
pub const AUDIO_OUTPUTS: &[&str] = &["display", "builtin", "auto"];

impl Profile {
    pub fn validate(&self) -> Result<()> {
        if !self.resolution.is_empty() {
            let ok = self.resolution.split_once('x').is_some_and(|(w, h)| {
                let dim = |s: &str| s.parse::<u32>().is_ok_and(|n| (320..=16384).contains(&n));
                dim(w) && dim(h)
            });
            ensure!(ok, "resolution must be WIDTHxHEIGHT, e.g. 1920x1080");
        }
        ensure!(VIEWS.contains(&self.view.as_str()), "unknown view {:?}", self.view);
        ensure!(DECODERS.contains(&self.preferred_decoder.as_str()), "unknown decoder {:?}", self.preferred_decoder);
        ensure!(CODECS.contains(&self.preferred_codec.as_str()), "unknown codec {:?}", self.preferred_codec);
        ensure!(self.display_sleep_minutes <= 1440, "display sleep must be at most 1440 minutes (a day)");
        ensure!(
            NETWORK_PROFILES.contains(&self.network_profile.as_str()),
            "unknown network profile {:?}",
            self.network_profile
        );
        ensure!(AUDIO_OUTPUTS.contains(&self.audio_output.as_str()), "unknown audio output {:?}", self.audio_output);
        Ok(())
    }

    /// This profile with `overrides`' fields in place of its own. Fields
    /// it doesn't have are skipped: one a newer veild stored, say.
    pub fn with(&self, overrides: &Overrides) -> Result<Profile> {
        let serde_json::Value::Object(mut fields) = serde_json::to_value(self)? else {
            bail!("a profile is a JSON object");
        };
        for (key, value) in overrides {
            if let Some(field) = fields.get_mut(key) {
                *field = value.clone();
            }
        }
        serde_json::from_value(serde_json::Value::Object(fields)).context("an override has the wrong type")
    }

    fn to_proto(&self) -> ClientProfile {
        ClientProfile {
            resolution: self.resolution.clone(),
            view: self.view.clone(),
            preferred_decoder: self.preferred_decoder.clone(),
            preferred_codec: self.preferred_codec.clone(),
            lossless_refinement: self.lossless_refinement,
            allow_pyrowave: self.allow_pyrowave,
            network_profile: self.network_profile.clone(),
            forward_gamepads: self.forward_gamepads,
            forward_security_keys: self.forward_security_keys,
            microphone: self.microphone,
            debug_logging: self.debug_logging,
            display_sleep_minutes: self.display_sleep_minutes,
            audio_output: self.audio_output.clone(),
        }
    }
}

/// What a client said about itself in its last hello, kept as JSON in
/// `thin_clients.last_report`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    pub hostname: String,
    pub ips: Vec<String>,
    /// The address Veil saw the connection come from.
    pub address: String,
    pub arch: String,
    pub image_version: String,
    pub boot_time_unix: i64,
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub memory_bytes: u64,
    pub gpus: Vec<Gpu>,
    pub hw_decode: Vec<String>,
    pub displays: Vec<Display>,
    pub nic_speed_mbps: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Gpu {
    pub name: String,
    pub driver: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Display {
    pub connector: String,
    pub width: u32,
    pub height: u32,
    pub refresh_mhz: u32,
}

impl Report {
    fn from_hello(hello: &WispHello, address: IpAddr) -> Report {
        let system = hello.system.clone().unwrap_or_default();
        Report {
            hostname: hello.hostname.clone(),
            ips: hello.ips.clone(),
            address: address.to_string(),
            arch: hello.arch.clone(),
            image_version: hello.image_version.clone(),
            // From the uptime, on Veil's clock: the client's may be hours off.
            boot_time_unix: if hello.uptime_secs > 0 { ipc::unix_now() - hello.uptime_secs as i64 } else { 0 },
            cpu_model: system.cpu_model,
            cpu_cores: system.cpu_cores,
            memory_bytes: system.memory_bytes,
            gpus: system.gpus.into_iter().map(|g| Gpu { name: g.name, driver: g.driver }).collect(),
            hw_decode: system.hw_decode,
            displays: system
                .displays
                .into_iter()
                .map(|d| Display { connector: d.connector, width: d.width, height: d.height, refresh_mhz: d.refresh_mhz })
                .collect(),
            nic_speed_mbps: system.nic_speed_mbps,
        }
    }
}

/// A session the client is running.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user: String,
    pub host_name: String,
    pub started_at: i64,
}

impl Session {
    /// Dated now, on Veil's clock: the client's may be hours off.
    fn from_proto(s: &ipc::wisp::WispSession) -> Option<Session> {
        (!s.user.is_empty() || !s.host_name.is_empty()).then(|| Session {
            user: s.user.clone(),
            host_name: s.host_name.clone(),
            started_at: ipc::unix_now(),
        })
    }
}

struct Live {
    generation: u64,
    conn: quinn::Connection,
    session: Option<Session>,
    /// To the connection's push task.
    commands: mpsc::UnboundedSender<WispAction>,
    /// Tells the push task the client's own settings changed.
    overrides_changed: Arc<Notify>,
}

/// One client as the admin UI shows it.
#[derive(Clone, Debug)]
pub struct ClientView {
    pub row: ThinClientRow,
    pub report: Report,
    pub online: bool,
    pub session: Option<Session>,
}

pub struct ThinClients {
    db: Arc<Db>,
    /// The shared key ([thin_clients] key); None: none configured, and
    /// every client is refused.
    key: Option<String>,
    online: Mutex<HashMap<String, Live>>,
    profile: watch::Sender<Profile>,
    generations: AtomicU64,
}

impl ThinClients {
    pub fn new(db: Arc<Db>, key: Option<String>) -> ThinClients {
        let profile = match db.setting(PROFILE_KEY) {
            Ok(Some(json)) => serde_json::from_str(&json).unwrap_or_else(|e| {
                warn!(error = %e, "thin clients: the stored profile doesn't parse; using the defaults");
                Profile::default()
            }),
            Ok(None) => Profile::default(),
            Err(e) => {
                warn!(error = %e, "thin clients: reading the profile failed; using the defaults");
                Profile::default()
            }
        };
        ThinClients {
            db,
            key,
            online: Mutex::new(HashMap::new()),
            profile: watch::Sender::new(profile),
            generations: AtomicU64::new(1),
        }
    }

    fn online(&self) -> std::sync::MutexGuard<'_, HashMap<String, Live>> {
        self.online.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn profile(&self) -> Profile {
        self.profile.borrow().clone()
    }

    /// Stores the defaults and pushes them to every connected client, with
    /// each one's own settings in their place.
    pub fn set_profile(&self, profile: Profile) -> Result<()> {
        profile.validate()?;
        self.db.set_setting(PROFILE_KEY, &serde_json::to_string(&profile)?)?;
        self.profile.send_replace(profile);
        Ok(())
    }

    /// The settings `mac` sets for itself; empty: none, or none readable.
    pub fn overrides(&self, mac: &str) -> Overrides {
        let json = match self.db.thin_client_overrides(mac) {
            Ok(Some(json)) => json,
            Ok(None) => return Overrides::new(),
            Err(e) => {
                warn!(mac, error = %e, "thin clients: reading a client's settings failed; using the defaults");
                return Overrides::new();
            }
        };
        serde_json::from_str(&json).unwrap_or_else(|e| {
            warn!(mac, error = %e, "thin clients: a client's stored settings don't parse; using the defaults");
            Overrides::new()
        })
    }

    /// What `mac` applies: the defaults with its own settings in place.
    pub fn effective_profile(&self, mac: &str) -> Profile {
        let defaults = self.profile();
        let overrides = self.overrides(mac);
        if overrides.is_empty() {
            return defaults;
        }
        match defaults.with(&overrides).and_then(|p| p.validate().map(|()| p)) {
            Ok(p) => p,
            Err(e) => {
                warn!(mac, error = %format!("{e:#}"), "thin clients: a client's stored settings don't apply; using the defaults");
                defaults
            }
        }
    }

    /// Replaces `mac`'s own settings (empty: back to the defaults) and
    /// pushes the result if it is online. False when there is no such
    /// client.
    pub fn set_overrides(&self, mac: &str, overrides: &Overrides) -> Result<bool> {
        let defaults = self.profile();
        let fields = serde_json::to_value(&defaults)?;
        for key in overrides.keys() {
            ensure!(fields.get(key).is_some(), "unknown setting {key:?}");
        }
        defaults.with(overrides)?.validate()?;
        let json = if overrides.is_empty() { None } else { Some(serde_json::to_string(overrides)?) };
        if !self.db.set_thin_client_overrides(mac, json.as_deref())? {
            return Ok(false);
        }
        if let Some(live) = self.online().get(mac) {
            live.overrides_changed.notify_one();
        }
        Ok(true)
    }

    pub fn is_online(&self, mac: &str) -> bool {
        self.online().contains_key(mac)
    }

    /// Every client Veil has heard from, online ones first, then by name.
    pub fn list(&self) -> Result<Vec<ClientView>> {
        let rows = self.db.thin_clients()?;
        let mut views: Vec<ClientView> = rows.into_iter().map(|row| self.view(row)).collect();
        views.sort_by(|a, b| {
            b.online.cmp(&a.online).then_with(|| a.display_name().to_lowercase().cmp(&b.display_name().to_lowercase()))
        });
        Ok(views)
    }

    pub fn get(&self, mac: &str) -> Result<Option<ClientView>> {
        Ok(self.db.thin_client(mac)?.map(|row| self.view(row)))
    }

    fn view(&self, row: ThinClientRow) -> ClientView {
        let report = serde_json::from_str(&row.last_report).unwrap_or_default();
        let (online, session) = match self.online().get(&row.mac) {
            Some(live) => (true, live.session.clone()),
            None => (false, None),
        };
        ClientView { row, report, online, session }
    }

    /// Drops a client's row. Refused while it is online: its next report
    /// would only bring it back.
    pub fn remove(&self, mac: &str) -> Result<bool> {
        if self.is_online(mac) {
            bail!("{mac} is online");
        }
        self.db.remove_thin_client(mac)
    }

    /// Sends an administrator's action to a connected client. False when
    /// it is offline. Fire and forget: the client's session report or its
    /// connection dropping is the answer.
    pub fn command(&self, mac: &str, action: WispAction) -> bool {
        self.online().get(mac).is_some_and(|live| live.commands.send(action).is_ok())
    }

    fn went_offline(&self, mac: &str, generation: u64) {
        let mut online = self.online();
        if online.get(mac).is_some_and(|l| l.generation == generation) {
            online.remove(mac);
            drop(online);
            let _ = self.db.touch_thin_client(mac);
            info!(mac, "thin clients: offline");
        }
    }

    fn set_session(&self, mac: &str, generation: u64, session: Option<Session>) {
        if let Some(live) = self.online().get_mut(mac).filter(|l| l.generation == generation) {
            live.session = session;
        }
    }
}

impl ClientView {
    /// The admin-given name, or the client's own hostname.
    pub fn display_name(&self) -> &str {
        if !self.row.name.is_empty() {
            &self.row.name
        } else if !self.report.hostname.is_empty() {
            &self.report.hostname
        } else {
            &self.row.mac
        }
    }
}

/// Reads [thin_clients] key: 64 hex digits, as `make install-veil` writes
/// them.
pub fn load_key(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let key = text.trim().to_ascii_lowercase();
    ensure!(
        key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit()),
        "{} must hold 64 hex digits",
        path.display()
    );
    Ok(key)
}

/// "52:54:00:12:34:56", lowercase; None for anything else.
fn normalize_mac(mac: &str) -> Option<String> {
    let mac = mac.trim().to_ascii_lowercase();
    let parts: Vec<&str> = mac.split(':').collect();
    let ok = parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then_some(mac)
}

/// Runs one `wisp/1` connection to its end. `slot` is the connection's
/// place under [auth] max_startups, released as soon as the key checks
/// out: an agent stays connected for as long as its client is up, and a
/// few of them holding slots would refuse every user's sign-in.
pub async fn serve(conn: quinn::Connection, veil: Arc<Veil>, slot: StartupSlot) {
    let peer = gdpnet::canonical(conn.remote_address());
    let code = match serve_inner(&conn, &veil, peer, slot).await {
        Ok(()) => 0,
        Err(e) => {
            let code = match e.downcast_ref::<Closed>() {
                Some(Closed(code)) => *code as u32,
                None => e.downcast_ref::<FrameError>().and_then(FrameError::close_code).unwrap_or(0),
            };
            if code == 0 {
                debug!(%peer, error = %format!("{e:#}"), "thin clients: connection ended");
            } else {
                warn!(%peer, error = %format!("{e:#}"), "thin clients: connection refused");
            }
            code
        }
    };
    conn.close(VarInt::from_u32(code), b"");
}

/// Ends the connection with this gdp-spec.md §12 code.
#[derive(Debug)]
struct Closed(LobbyErrorCode);

impl std::fmt::Display for Closed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "closing with {}", self.0.as_str_name())
    }
}

impl std::error::Error for Closed {}

async fn serve_inner(conn: &quinn::Connection, veil: &Arc<Veil>, peer: SocketAddr, slot: StartupSlot) -> Result<()> {
    let thin = &veil.thin_clients;
    // The same deadline as a login's, from the handshake.
    let grace = veil.config.auth.login_grace_time;
    let deadline = Instant::now() + if grace.is_zero() { Duration::from_secs(120) } else { grace };
    let first = async {
        let (send, mut recv) = conn.accept_bi().await?;
        let hello: WispEnvelope = read_frame_max(&mut recv, MAX_FRAME).await?;
        Ok::<_, anyhow::Error>((send, recv, hello))
    };
    let (mut send, mut recv, hello) = match timeout_at(deadline, first).await {
        Ok(Ok(first)) => first,
        Ok(Err(e)) => {
            veil.penalties.penalise(peer.ip(), Offense::NoAuth);
            return Err(e.context("reading the hello"));
        }
        Err(_) => {
            veil.penalties.penalise(peer.ip(), Offense::GraceExceeded);
            bail!(Closed(LobbyErrorCode::LobbyErrorAuthFailed));
        }
    };
    let Some(Msg::Hello(hello)) = hello.msg else {
        veil.penalties.penalise(peer.ip(), Offense::NoAuth);
        return Err(anyhow::anyhow!(Closed(LobbyErrorCode::LobbyErrorMalformedFrame)).context("expected WispHello"));
    };
    // A wrong key costs the address nothing: after a key rotation, every
    // client still on the old one would otherwise lock its own greeter's
    // sign-ins out too. The agent's backoff paces its retries, and the key
    // is too long to guess.
    let Some(key) = &thin.key else {
        return Err(anyhow::anyhow!(Closed(LobbyErrorCode::LobbyErrorAuthFailed))
            .context("no [thin_clients] key configured, so no thin client can connect"));
    };
    if !constant_time_eq(hello.key.trim().to_ascii_lowercase().as_bytes(), key.as_bytes()) {
        return Err(anyhow::anyhow!(Closed(LobbyErrorCode::LobbyErrorAuthFailed))
            .context(format!("wrong Wisp key from {} ({})", hello.mac, hello.hostname)));
    }
    drop(slot);
    let Some(mac) = normalize_mac(&hello.mac) else {
        return Err(anyhow::anyhow!(Closed(LobbyErrorCode::LobbyErrorMalformedFrame))
            .context(format!("bad MAC address {:?}", hello.mac)));
    };

    let report = Report::from_hello(&hello, peer.ip());
    thin.db.thin_client_seen(&mac, &serde_json::to_string(&report)?)?;
    let mut profile = thin.profile.subscribe();
    profile.mark_unchanged();
    let mut sent = thin.effective_profile(&mac).to_proto();
    let welcome = WispWelcome { profile: Some(sent.clone()) };
    write_frame(&mut send, &WispEnvelope { msg: Some(Msg::Welcome(welcome)) }).await?;

    let generation = thin.generations.fetch_add(1, Ordering::Relaxed);
    let session = hello.session.as_ref().and_then(Session::from_proto);
    let (commands, mut command_rx) = mpsc::unbounded_channel();
    let overrides_changed = Arc::new(Notify::new());
    // A change to the client's own settings since the welcome was read.
    overrides_changed.notify_one();
    let live = Live { generation, conn: conn.clone(), session, commands, overrides_changed: overrides_changed.clone() };
    if let Some(old) = thin.online().insert(mac.clone(), live) {
        old.conn.close(VarInt::from_u32(0), b"replaced by a newer connection");
    }
    info!(%peer, mac, hostname = %hello.hostname, image = %hello.image_version, "thin clients: online");

    // Profile pushes and commands go out from their own task, so the read
    // below is never cancelled halfway through a frame. A change to the
    // defaults that the client's own settings override sends nothing.
    let veil_ = veil.clone();
    let mac_ = mac.clone();
    let pusher = tokio::spawn(async move {
        loop {
            let msg = tokio::select! {
                changed = profile.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    profile.mark_unchanged();
                    None
                }
                () = overrides_changed.notified() => None,
                Some(action) = command_rx.recv() => Some(Msg::Command(WispCommand { action: action as i32 })),
            };
            let msg = match msg {
                Some(msg) => msg,
                None => {
                    let now = veil_.thin_clients.effective_profile(&mac_).to_proto();
                    if now == sent {
                        continue;
                    }
                    sent = now.clone();
                    Msg::Profile(WispProfile { profile: Some(now) })
                }
            };
            if write_frame(&mut send, &WispEnvelope { msg: Some(msg) }).await.is_err() {
                break;
            }
        }
    });
    let result = async {
        loop {
            let env: WispEnvelope = match read_frame_max(&mut recv, MAX_FRAME).await {
                Ok(env) => env,
                // The agent going away (a reboot, a shutdown) ends its
                // stream or connection.
                Err(FrameError::Io(_)) => return Ok(()),
                Err(e) => return Err(anyhow::Error::from(e)),
            };
            match env.msg {
                Some(Msg::Session(s)) => {
                    let session = Session::from_proto(&s);
                    match &session {
                        Some(s) => info!(mac, user = %s.user, host = %s.host_name, "thin clients: session started"),
                        None => info!(mac, "thin clients: session ended"),
                    }
                    thin.set_session(&mac, generation, session);
                }
                other => bail!("unexpected message from a thin client: {other:?}"),
            }
        }
    }
    .await;
    pusher.abort();
    thin.went_offline(&mac, generation);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macs_are_normalized_or_refused() {
        assert_eq!(normalize_mac(" 52:54:00:AB:cd:0F ").as_deref(), Some("52:54:00:ab:cd:0f"));
        assert_eq!(normalize_mac("525400abcd0f"), None);
        assert_eq!(normalize_mac("52:54:00:ab:cd"), None);
        assert_eq!(normalize_mac("52:54:00:ab:cd:zz"), None);
    }

    #[test]
    fn profiles_are_checked() {
        Profile::default().validate().unwrap();
        let ok = Profile { resolution: "1920x1080".into(), view: "actual".into(), preferred_codec: "av1".into(), ..Default::default() };
        ok.validate().unwrap();
        for bad in [
            Profile { resolution: "1920".into(), ..Default::default() },
            Profile { resolution: "1x1".into(), ..Default::default() },
            Profile { view: "zoom".into(), ..Default::default() },
            Profile { preferred_decoder: "vaapi".into(), ..Default::default() },
            Profile { preferred_codec: "vp9".into(), ..Default::default() },
            Profile { network_profile: "".into(), ..Default::default() },
            Profile { display_sleep_minutes: 1441, ..Default::default() },
            Profile { audio_output: "hdmi".into(), ..Default::default() },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_profile_survives_a_restart_and_reaches_subscribers() {
        let db = Arc::new(Db::in_memory());
        let thin = ThinClients::new(db.clone(), None);
        assert_eq!(thin.profile(), Profile::default());
        let mut rx = thin.profile.subscribe();
        let changed = Profile { lossless_refinement: false, network_profile: "lan".into(), ..Default::default() };
        thin.set_profile(changed.clone()).unwrap();
        assert!(rx.has_changed().unwrap());
        assert_eq!(*rx.borrow_and_update(), changed);
        assert!(thin.set_profile(Profile { view: "nope".into(), ..Default::default() }).is_err());
        assert_eq!(ThinClients::new(db, None).profile(), changed);
    }

    fn overrides(json: serde_json::Value) -> Overrides {
        json.as_object().unwrap().clone()
    }

    #[test]
    fn a_clients_own_settings_override_the_defaults() {
        let db = Arc::new(Db::in_memory());
        let thin = ThinClients::new(db.clone(), None);
        let mac = "52:54:00:12:34:56";
        assert!(!thin.set_overrides(mac, &overrides(serde_json::json!({"view": "fit"}))).unwrap());
        db.thin_client_seen(mac, "{}").unwrap();
        thin.set_overrides(mac, &overrides(serde_json::json!({"audio_output": "builtin", "display_sleep_minutes": 0})))
            .unwrap();
        thin.set_profile(Profile { network_profile: "lan".into(), display_sleep_minutes: 5, ..Default::default() })
            .unwrap();
        let p = thin.effective_profile(mac);
        assert_eq!((p.audio_output.as_str(), p.display_sleep_minutes, p.network_profile.as_str()), ("builtin", 0, "lan"));
        assert_eq!(thin.effective_profile("52:54:00:00:00:01").display_sleep_minutes, 5);
        thin.set_overrides(mac, &Overrides::new()).unwrap();
        assert_eq!(thin.effective_profile(mac), thin.profile());
        assert_eq!(db.thin_client_overrides(mac).unwrap(), None);
    }

    #[test]
    fn a_clients_own_settings_are_checked() {
        let db = Arc::new(Db::in_memory());
        let thin = ThinClients::new(db.clone(), None);
        let mac = "52:54:00:12:34:56";
        db.thin_client_seen(mac, "{}").unwrap();
        for bad in [
            serde_json::json!({"audio_output": "hdmi"}),
            serde_json::json!({"microphone": "yes"}),
            serde_json::json!({"no_such_setting": true}),
        ] {
            assert!(thin.set_overrides(mac, &overrides(bad.clone())).is_err(), "{bad}");
        }
        assert!(thin.overrides(mac).is_empty());
        // One stored by a newer veild is skipped, the rest still apply.
        db.set_thin_client_overrides(mac, Some(r#"{"view":"fit","from_the_future":1}"#)).unwrap();
        assert_eq!(thin.effective_profile(mac).view, "fit");
    }

    #[test]
    fn keys_must_be_64_hex_digits() {
        let dir = std::env::temp_dir().join(format!("veil-wisp-key-{}", std::process::id()));
        std::fs::write(&dir, format!("{}\n", "AB".repeat(32))).unwrap();
        assert_eq!(load_key(&dir).unwrap(), "ab".repeat(32));
        std::fs::write(&dir, "abc").unwrap();
        assert!(load_key(&dir).is_err());
        std::fs::remove_file(&dir).unwrap();
    }
}
