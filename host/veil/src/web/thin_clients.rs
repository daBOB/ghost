// SPDX-FileCopyrightText: 2026 Joseph Saiko <https://saiko.dev>
// SPDX-License-Identifier: GPL-3.0-only

// The admin UI's Thin Clients pages (docs/design/wisp.md): the list of
// Wisp clients, one client's report with log out, restart and shut down,
// the default settings every client applies, and one client's own. The live state is
// crate::thin_clients'.
use std::collections::HashMap;

use askama::Template;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::Form;
use ipc::unix_now as now;
use ipc::wisp::WispAction;
use serde::Deserialize;

use super::{ago, error_page, has_control, internal, render, utc, Admin, CsrfForm, Nav, NoticeQuery, WebState};
use crate::thin_clients::{ClientView, Overrides, Profile, Report, CODECS};

/// Offered after "Match the client's display", as in spectre-qt's dialog.
const RESOLUTIONS: &[&str] = &["1280x720", "1366x768", "1600x900", "1920x1080", "2560x1440", "3840x2160"];

struct ClientRow {
    mac: String,
    name: String,
    hostname: String,
    online: bool,
    address: String,
    user: String,
    host_name: String,
    uptime: String,
    last_seen: String,
}

impl ClientRow {
    fn new(c: &ClientView, t: i64) -> ClientRow {
        let session = c.session.clone();
        ClientRow {
            mac: c.row.mac.clone(),
            name: c.display_name().to_string(),
            hostname: c.report.hostname.clone(),
            online: c.online,
            address: c.report.address.clone(),
            user: session.as_ref().map(|s| s.user.clone()).unwrap_or_default(),
            host_name: session.map(|s| s.host_name).unwrap_or_default(),
            uptime: if c.online && c.report.boot_time_unix > 0 { duration(t - c.report.boot_time_unix) } else { String::new() },
            last_seen: if c.online { "now".to_string() } else { ago(t, c.row.last_seen) },
        }
    }
}

/// "3 d 4 h", "2 h 5 min", "12 min".
fn duration(secs: i64) -> String {
    let secs = secs.max(0);
    let (d, h, m) = (secs / 86400, secs % 86400 / 3600, secs % 3600 / 60);
    match (d, h) {
        (0, 0) => format!("{m} min"),
        (0, _) => format!("{h} h {m} min"),
        _ => format!("{d} d {h} h"),
    }
}

fn rows(state: &WebState) -> anyhow::Result<Vec<ClientRow>> {
    let t = now();
    Ok(state.veil.thin_clients.list()?.iter().map(|c| ClientRow::new(c, t)).collect())
}

/// Feeds mod.rs's state_digest: the rows as shown plus each client's
/// report, which the detail pages show more of.
pub(super) fn digest(veil: &crate::Veil, h: &mut impl std::hash::Hasher) {
    use std::hash::Hash;
    let Ok(list) = veil.thin_clients.list() else { return };
    let t = now();
    for c in &list {
        let r = ClientRow::new(c, t);
        (&r.mac, &r.name, &r.hostname, r.online, &r.address, &r.user, &r.host_name, &r.uptime, &r.last_seen).hash(h);
        format!("{:?}", c.report).hash(h);
        c.session.as_ref().map(|s| s.started_at).hash(h);
    }
}

// Notices after a redirect, from a fixed list (as mod.rs's notice_text).
fn notice_text(key: &str) -> String {
    match key {
        "saved" => "Saved.",
        "renamed" => "Name saved.",
        "removed" => "Thin client removed.",
        "log_out" => "Ending the session. The client returns to its sign-in screen once the host ends the session.",
        "reboot" => "Restarting.",
        "power_off" => "Shutting down.",
        _ => "",
    }
    .to_string()
}

#[derive(Template)]
#[template(path = "thin_clients.html")]
struct ListPage {
    nav: Nav,
    rows: Vec<ClientRow>,
    online: usize,
    total: usize,
}

#[derive(Template)]
#[template(path = "thin_client_rows.html")]
struct RowsPartial {
    rows: Vec<ClientRow>,
}

pub(super) async fn list(State(state): State<WebState>, admin: Admin, Query(q): Query<NoticeQuery>) -> Response {
    let rows = match rows(&state) {
        Ok(rows) => rows,
        Err(e) => return internal(e),
    };
    render(&ListPage {
        online: rows.iter().filter(|r| r.online).count(),
        total: rows.len(),
        rows,
        nav: admin.nav("thin_clients", notice_text(&q.notice)),
    })
}

pub(super) async fn list_rows(State(state): State<WebState>, _admin: Admin) -> Response {
    match rows(&state) {
        Ok(rows) => render(&RowsPartial { rows }),
        Err(e) => internal(e),
    }
}

#[derive(Template)]
#[template(path = "thin_client.html")]
struct DetailPage {
    nav: Nav,
    c: ClientRow,
    report: Report,
    custom_name: String,
    booted: String,
    first_seen: String,
    session_since: String,
    memory: String,
    displays: Vec<String>,
    /// The settings it sets itself: (label, value).
    own_settings: Vec<(String, String)>,
}

pub(super) async fn detail(
    State(state): State<WebState>,
    admin: Admin,
    Path(mac): Path<String>,
    Query(q): Query<NoticeQuery>,
) -> Response {
    let view = match state.veil.thin_clients.get(&mac) {
        Ok(Some(view)) => view,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed."),
        Err(e) => return internal(e),
    };
    let t = now();
    let report = view.report.clone();
    let displays = report
        .displays
        .iter()
        .map(|d| {
            let mut s = format!("{} {}x{}", d.connector, d.width, d.height);
            if d.refresh_mhz > 0 {
                s += &format!(" @ {:.2} Hz", d.refresh_mhz as f64 / 1000.0);
            }
            s
        })
        .collect();
    render(&DetailPage {
        nav: admin.nav("thin_clients", notice_text(&q.notice)),
        c: ClientRow::new(&view, t),
        custom_name: view.row.name.clone(),
        booted: if report.boot_time_unix > 0 { utc(report.boot_time_unix) } else { "unknown".into() },
        first_seen: utc(view.row.first_seen),
        session_since: view.session.as_ref().filter(|s| s.started_at > 0).map(|s| ago(t, s.started_at)).unwrap_or_default(),
        memory: if report.memory_bytes > 0 {
            format!("{:.1} GiB", report.memory_bytes as f64 / (1u64 << 30) as f64)
        } else {
            "unknown".into()
        },
        displays,
        own_settings: own_settings(&state.veil.thin_clients.overrides(&mac)),
        report,
    })
}

#[derive(Deserialize)]
pub(super) struct NameForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    name: String,
}

pub(super) async fn rename(
    State(state): State<WebState>,
    admin: Admin,
    headers: HeaderMap,
    Path(mac): Path<String>,
    Form(form): Form<NameForm>,
) -> Response {
    if let Err(r) = admin.check_csrf(&headers, &form.csrf) {
        return r;
    }
    let name = form.name.trim();
    if name.len() > 64 || has_control(name) {
        return error_page(StatusCode::BAD_REQUEST, "Not saved", "The name must be at most 64 characters, without control characters.");
    }
    let veil = &state.veil;
    let before = match veil.db.thin_client(&mac) {
        Ok(Some(row)) => row.name,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed."),
        Err(e) => return internal(e),
    };
    if before != name {
        if let Err(e) = veil.db.rename_thin_client(&mac, name) {
            return internal(e);
        }
        veil.db.audit(&admin.username, "thin client renamed", None, &format!("{mac}: {before:?} -> {name:?}"), None);
    }
    Redirect::to(&format!("/admin/thin-clients/{mac}?notice=renamed")).into_response()
}

pub(super) async fn remove(
    State(state): State<WebState>,
    admin: Admin,
    headers: HeaderMap,
    Path(mac): Path<String>,
    Form(form): Form<CsrfForm>,
) -> Response {
    if let Err(r) = admin.check_csrf(&headers, &form.csrf) {
        return r;
    }
    let thin = &state.veil.thin_clients;
    let name = thin.get(&mac).ok().flatten().map(|c| c.display_name().to_string()).unwrap_or_default();
    if thin.is_online(&mac) {
        return error_page(StatusCode::CONFLICT, "Not removed", "The client is online; it would only report back in.");
    }
    match thin.remove(&mac) {
        Ok(true) => {
            state.veil.db.audit(&admin.username, "thin client removed", None, &format!("{mac} ({name})"), None);
            Redirect::to("/admin/thin-clients?notice=removed").into_response()
        }
        Ok(false) => error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed already."),
        Err(e) => internal(e),
    }
}

#[derive(Deserialize)]
pub(super) struct ActionForm {
    #[serde(default)]
    csrf: String,
    #[serde(default)]
    action: String,
}

/// Log out, restart or shut down, sent to the client's agent.
pub(super) async fn act(
    State(state): State<WebState>,
    admin: Admin,
    headers: HeaderMap,
    Path(mac): Path<String>,
    Form(form): Form<ActionForm>,
) -> Response {
    if let Err(r) = admin.check_csrf(&headers, &form.csrf) {
        return r;
    }
    let (action, audit) = match form.action.as_str() {
        "log_out" => (WispAction::LogOut, "thin client logged out"),
        "reboot" => (WispAction::Reboot, "thin client restarted"),
        "power_off" => (WispAction::PowerOff, "thin client shut down"),
        _ => return error_page(StatusCode::BAD_REQUEST, "Nothing done", "Unknown action."),
    };
    let thin = &state.veil.thin_clients;
    let view = match thin.get(&mac) {
        Ok(Some(view)) => view,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed."),
        Err(e) => return internal(e),
    };
    if action == WispAction::LogOut && view.session.is_none() {
        return error_page(StatusCode::CONFLICT, "Nothing done", "Nobody is signed in on this client.");
    }
    if !thin.command(&mac, action) {
        return error_page(StatusCode::CONFLICT, "Nothing done", "The client is offline.");
    }
    let mut detail = format!("{mac} ({})", view.display_name());
    if let Some(s) = view.session.as_ref().filter(|s| !s.user.is_empty()) {
        detail += &format!(", {} signed in", s.user);
    }
    state.veil.db.audit(&admin.username, audit, None, &detail, None);
    Redirect::to(&format!("/admin/thin-clients/{mac}?notice={}", form.action)).into_response()
}
// --- settings: the defaults, and one client's own ---

/// One setting, as both settings pages show it. `key` is its Profile
/// field's JSON name.
struct Field {
    key: &'static str,
    label: &'static str,
    /// HTML.
    hint: &'static str,
    kind: Kind,
}

enum Kind {
    /// (value, label)
    Choice(Vec<(String, String)>),
    Flag,
    Minutes,
}

struct Section {
    title: &'static str,
    fields: Vec<Field>,
}

fn choices(list: &[(&str, &str)]) -> Kind {
    Kind::Choice(list.iter().map(|(v, l)| (v.to_string(), l.to_string())).collect())
}

/// Every setting, laid out like spectre-qt's Settings dialog minus what a
/// kiosk makes moot, then the client's own.
fn sections() -> Vec<Section> {
    let mut resolutions = vec![(String::new(), "Match the client's display".to_string())];
    resolutions.extend(RESOLUTIONS.iter().map(|r| (r.to_string(), r.to_string())));
    let field = |key, label, hint, kind| Field { key, label, hint, kind };
    vec![
        Section {
            title: "Display",
            fields: vec![
                field("resolution", "Resolution", "", Kind::Choice(resolutions)),
                field(
                    "view",
                    "View",
                    "Fit to window scales the remote desktop to the screen. Actual size shows it pixel for pixel, panned by pushing the pointer against an edge when it is bigger.",
                    choices(&[("", "As last set in the session menu"), ("fit", "Fit to window"), ("actual", "Actual size")]),
                ),
            ],
        },
        Section {
            title: "Decoding",
            fields: vec![field(
                "preferred_decoder",
                "Preferred decoder",
                "Which decoder to try first. A hardware decoder that isn't available falls back to the other one, then to software. NVIDIA cards never use VA-API, since they have none.",
                choices(&[("vulkan", "Vulkan Video"), ("native", "VA-API"), ("software", "Software")]),
            )],
        },
        Section {
            title: "Codec",
            fields: vec![
                field(
                    "preferred_codec",
                    "Video codec",
                    "Which codec to offer first. The host picks the first one it can encode: a preference, not a demand.",
                    Kind::Choice(codec_choices()),
                ),
                field(
                    "lossless_refinement",
                    "Start sessions lossless",
                    "Once a region of the screen stops changing, the host re-sends it losslessly so text and UI become pixel-exact. Costs the host a frame readback per frame. Off, every session starts with it off; either way the session menu's Lossless Refinement row switches it.",
                    Kind::Flag,
                ),
                field(
                    "allow_pyrowave",
                    "Use PyroWave on a wired LAN",
                    "The lowest latency there is, at several hundred Mbit/s: offered first only when the host is directly reachable over a wired link of 1 Gbit/s or more, and used only if the host has turned it on.",
                    Kind::Flag,
                ),
            ],
        },
        Section {
            title: "Network",
            fields: vec![field(
                "network_profile",
                "Connection",
                "What kind of link the client is on, so the host can pace the stream to it. Auto lets the host work it out from what it measures.",
                choices(&[("auto", "Auto"), ("lan", "LAN"), ("internet", "Internet"), ("mobile", "Mobile / lossy Wi-Fi")]),
            )],
        },
        Section {
            title: "Input",
            fields: vec![
                field(
                    "forward_gamepads",
                    "Forward gamepads",
                    "Mirror controllers plugged into the client onto the host as virtual gamepads (up to four), if the host supports it.",
                    Kind::Flag,
                ),
                field(
                    "forward_security_keys",
                    "Forward security keys",
                    "Let the host's browsers sign in with FIDO security keys (a YubiKey, say) plugged into the client, if the host supports it. While forwarded, anything in the session can ask a key to sign in to any site; only a touch on the key approves it. Off by default.",
                    Kind::Flag,
                ),
                field(
                    "microphone",
                    "Send microphone",
                    "Send the client's microphone to the host, where applications see it as a microphone, if the host supports it. Off by default.",
                    Kind::Flag,
                ),
            ],
        },
        Section {
            title: "Audio",
            fields: vec![field(
                "audio_output",
                "Play sound through",
                "The display: the monitor's or TV's speakers, over HDMI or DisplayPort, kept while the display sleeps. Built-in: the client's own speaker or audio jack. Automatic: whatever the client picks itself, which on many PCs is the built-in speaker. Applies at once, in a running session too.",
                choices(&[
                    ("display", "The display (HDMI/DisplayPort)"),
                    ("builtin", "Built-in speaker or audio jack"),
                    ("auto", "Automatic"),
                ]),
            )],
        },
        Section {
            title: "Diagnostics",
            fields: vec![field(
                "debug_logging",
                "Enable Spectre debug logging",
                "Run spectre with its debug log on: more detail in the client's journal, and in the client's half of a support report (<code>wraith --report</code> on the host). For chasing a problem; off by default.",
                Kind::Flag,
            )],
        },
        Section {
            title: "Power",
            fields: vec![field(
                "display_sleep_minutes",
                "Turn the display off after",
                "Without keyboard, mouse or gamepad input, at the sign-in screen or in a session. Any input wakes it. 0: never.",
                Kind::Minutes,
            )],
        },
    ]
}

fn codec_choices() -> Vec<(String, String)> {
    CODECS
        .iter()
        .map(|&c| {
            let label = match c {
                "" => "Auto".to_string(),
                "h265" => "h265 (req. hardware)".to_string(),
                "av1" => "av1 (req. newer hardware)".to_string(),
                "pyrowave" => "pyrowave (wired LAN only)".to_string(),
                other => other.to_string(),
            };
            (c.to_string(), label)
        })
        .collect()
}

/// The form value a client's page uses for "the default's".
const INHERIT: &str = "inherit";

/// A field as the template renders it: `kind` "choice", "flag" (a
/// checkbox) or "minutes". On a client's page a flag is a choice too, of
/// the default's, on and off.
struct FieldView {
    key: &'static str,
    label: &'static str,
    hint: &'static str,
    kind: &'static str,
    options: Vec<ChoiceView>,
    checked: bool,
    /// A minutes field's value; empty on a client's page: the default's.
    value: String,
    placeholder: String,
    /// The client sets this one itself.
    overridden: bool,
}

struct ChoiceView {
    value: String,
    label: String,
    selected: bool,
}

struct SectionView {
    title: &'static str,
    fields: Vec<FieldView>,
}

fn profile_fields(p: &Profile) -> serde_json::Map<String, serde_json::Value> {
    match serde_json::to_value(p) {
        Ok(serde_json::Value::Object(fields)) => fields,
        _ => serde_json::Map::new(),
    }
}

/// How `value` reads on the page: a choice's label, "On"/"Off", or the
/// number.
fn value_label(field: &Field, value: &serde_json::Value) -> String {
    match (&field.kind, value) {
        (Kind::Choice(list), serde_json::Value::String(s)) => {
            list.iter().find(|(v, _)| v == s).map(|(_, l)| l.clone()).unwrap_or_else(|| s.clone())
        }
        (_, serde_json::Value::Bool(b)) => if *b { "On" } else { "Off" }.to_string(),
        (Kind::Minutes, serde_json::Value::Number(n)) => format!("{n} min"),
        (_, other) => other.to_string(),
    }
}

/// The defaults page shows `defaults`; a client's page (`overrides` set)
/// shows what the client sets itself, and the default's for the rest.
fn section_views(defaults: &Profile, overrides: Option<&Overrides>) -> Vec<SectionView> {
    let base = profile_fields(defaults);
    sections()
        .into_iter()
        .map(|s| SectionView {
            title: s.title,
            fields: s
                .fields
                .iter()
                .map(|f| {
                    let default = base.get(f.key).cloned().unwrap_or(serde_json::Value::Null);
                    let own = overrides.and_then(|o| o.get(f.key));
                    let shown = own.unwrap_or(&default);
                    // The value itself is selected unless the client's page
                    // leaves it at the default's.
                    let pick = overrides.is_none() || own.is_some();
                    let mut view = FieldView {
                        key: f.key,
                        label: f.label,
                        hint: f.hint,
                        kind: "choice",
                        options: Vec::new(),
                        checked: false,
                        value: String::new(),
                        placeholder: String::new(),
                        overridden: own.is_some(),
                    };
                    let mut option = |value: &str, label: String, selected: bool| {
                        view.options.push(ChoiceView { value: value.to_string(), label, selected })
                    };
                    if overrides.is_some() && !matches!(f.kind, Kind::Minutes) {
                        option(INHERIT, format!("Default ({})", value_label(f, &default)), own.is_none());
                    }
                    match &f.kind {
                        Kind::Choice(list) => {
                            let current = shown.as_str().unwrap_or_default();
                            for (value, label) in list {
                                option(value, label.clone(), pick && value == current);
                            }
                            // A value the list doesn't offer (a resolution
                            // set elsewhere) stays selectable.
                            if pick && !list.iter().any(|(v, _)| v == current) {
                                option(current, current.to_string(), true);
                            }
                        }
                        Kind::Flag if overrides.is_some() => {
                            let on = own.and_then(|v| v.as_bool());
                            option("on", "On".into(), on == Some(true));
                            option("off", "Off".into(), on == Some(false));
                        }
                        Kind::Flag => {
                            view.kind = "flag";
                            view.checked = shown.as_bool().unwrap_or(false);
                        }
                        Kind::Minutes => {
                            view.kind = "minutes";
                            match overrides {
                                Some(_) => {
                                    view.value = own.map(|v| v.to_string()).unwrap_or_default();
                                    view.placeholder = format!("{default} (default)");
                                }
                                None => view.value = shown.to_string(),
                            }
                        }
                    }
                    view
                })
                .collect(),
        })
        .collect()
}

/// The form's settings: every field for the defaults page; only the ones
/// not left at the default's for a client's page (`own`). Err: the message
/// to show.
fn parse_fields(form: &HashMap<String, String>, own: bool) -> Result<Overrides, String> {
    let mut fields = Overrides::new();
    for s in sections() {
        for f in &s.fields {
            let raw = form.get(f.key).map(|v| v.trim()).unwrap_or_default();
            let value = match &f.kind {
                _ if own && raw == INHERIT => continue,
                Kind::Minutes if own && raw.is_empty() => continue,
                Kind::Choice(_) => serde_json::Value::String(raw.to_string()),
                Kind::Flag if own => match raw {
                    "on" => serde_json::Value::Bool(true),
                    "off" => serde_json::Value::Bool(false),
                    _ => return Err(format!("{} must be the default's, on or off.", f.label)),
                },
                // A checkbox: absent when unticked.
                Kind::Flag => serde_json::Value::Bool(!raw.is_empty()),
                Kind::Minutes => match raw.parse::<u32>() {
                    Ok(n) => n.into(),
                    Err(_) => return Err(format!("{} must be a whole number of minutes.", f.label)),
                },
            };
            fields.insert(f.key.to_string(), value);
        }
    }
    Ok(fields)
}

/// "network_profile auto -> lan, lossless_refinement on -> off", for the
/// audit log; a field one side lacks reads "default" there.
fn describe_changes(before: &Overrides, after: &Overrides) -> String {
    let show = |v: Option<&serde_json::Value>| match v {
        None => "default".to_string(),
        Some(serde_json::Value::Bool(true)) => "on".to_string(),
        Some(serde_json::Value::Bool(false)) => "off".to_string(),
        Some(serde_json::Value::String(s)) if s.is_empty() => "default".to_string(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    };
    let mut keys: Vec<&String> = before.keys().chain(after.keys()).collect();
    keys.sort();
    keys.dedup();
    keys.into_iter()
        .filter(|k| before.get(*k) != after.get(*k))
        .map(|k| format!("{k} {} -> {}", show(before.get(k)), show(after.get(k))))
        .collect::<Vec<_>>()
        .join(", ")
}

/// What a client sets itself, as its page's summary shows it: (label,
/// value).
fn own_settings(overrides: &Overrides) -> Vec<(String, String)> {
    sections()
        .iter()
        .flat_map(|s| &s.fields)
        .filter_map(|f| overrides.get(f.key).map(|v| (f.label.to_string(), value_label(f, v))))
        .collect()
}

#[derive(Template)]
#[template(path = "thin_client_settings.html")]
struct SettingsPage {
    nav: Nav,
    sections: Vec<SectionView>,
    /// Set on a client's page.
    client: Option<SettingsClient>,
}

struct SettingsClient {
    mac: String,
    name: String,
    own: usize,
}

pub(super) async fn settings(State(state): State<WebState>, admin: Admin, Query(q): Query<NoticeQuery>) -> Response {
    render(&SettingsPage {
        nav: admin.nav("thin_clients", notice_text(&q.notice)),
        sections: section_views(&state.veil.thin_clients.profile(), None),
        client: None,
    })
}

pub(super) async fn save_settings(
    State(state): State<WebState>,
    admin: Admin,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(r) = admin.check_csrf(&headers, form.get("csrf").map(String::as_str).unwrap_or_default()) {
        return r;
    }
    let thin = &state.veil.thin_clients;
    let before = thin.profile();
    let profile = match parse_fields(&form, false).map(|fields| before.with(&fields)) {
        Ok(Ok(profile)) => profile,
        Ok(Err(e)) => return error_page(StatusCode::BAD_REQUEST, "Not saved", &format!("{e:#}.")),
        Err(message) => return error_page(StatusCode::BAD_REQUEST, "Not saved", &message),
    };
    if let Err(e) = profile.validate() {
        return error_page(StatusCode::BAD_REQUEST, "Not saved", &format!("{e}."));
    }
    if profile != before {
        if let Err(e) = thin.set_profile(profile.clone()) {
            return internal(e);
        }
        let detail = describe_changes(&profile_fields(&before), &profile_fields(&profile));
        state.veil.db.audit(&admin.username, "thin client settings changed", None, &detail, None);
    }
    Redirect::to("/admin/thin-clients/settings?notice=saved").into_response()
}

pub(super) async fn client_settings(
    State(state): State<WebState>,
    admin: Admin,
    Path(mac): Path<String>,
    Query(q): Query<NoticeQuery>,
) -> Response {
    let thin = &state.veil.thin_clients;
    let view = match thin.get(&mac) {
        Ok(Some(view)) => view,
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed."),
        Err(e) => return internal(e),
    };
    let overrides = thin.overrides(&mac);
    render(&SettingsPage {
        nav: admin.nav("thin_clients", notice_text(&q.notice)),
        sections: section_views(&thin.profile(), Some(&overrides)),
        client: Some(SettingsClient { name: view.display_name().to_string(), mac, own: overrides.len() }),
    })
}

/// A client's own settings, or with `reset` back to the defaults.
pub(super) async fn save_client_settings(
    State(state): State<WebState>,
    admin: Admin,
    headers: HeaderMap,
    Path(mac): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if let Err(r) = admin.check_csrf(&headers, form.get("csrf").map(String::as_str).unwrap_or_default()) {
        return r;
    }
    let thin = &state.veil.thin_clients;
    let name = match thin.get(&mac) {
        Ok(Some(view)) => view.display_name().to_string(),
        Ok(None) => return error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed."),
        Err(e) => return internal(e),
    };
    let after = if form.contains_key("reset") {
        Overrides::new()
    } else {
        match parse_fields(&form, true) {
            Ok(fields) => fields,
            Err(message) => return error_page(StatusCode::BAD_REQUEST, "Not saved", &message),
        }
    };
    let before = thin.overrides(&mac);
    if after != before {
        match thin.set_overrides(&mac, &after) {
            Ok(true) => {}
            Ok(false) => return error_page(StatusCode::NOT_FOUND, "No such thin client", "It may have been removed."),
            Err(e) => return error_page(StatusCode::BAD_REQUEST, "Not saved", &format!("{e:#}.")),
        }
        let detail = format!("{mac} ({name}): {}", describe_changes(&before, &after));
        state.veil.db.audit(&admin.username, "thin client's own settings changed", None, &detail, None);
    }
    Redirect::to(&format!("/admin/thin-clients/{mac}/settings?notice=saved")).into_response()
}
