# 0015. Security keys pass through with a fixed descriptor

Status: Accepted (2026-10-18); maintenance by consent since [0016](0016-key-maintenance-by-consent.md)

## Context

A user with a FIDO2/U2F security key (a YubiKey, a SoloKey) at the
client wants to use it in the session: to sign in to a web page in the
host's Chrome or Firefox, or anywhere else libfido2 is used. Over USB a
key's FIDO interface is a HID device with one top-level collection on
the FIDO Alliance usage page (`0xF1D0`, usage `0x01`) and 64-byte input
and output reports, and CTAPHID, the protocol on it, uses nothing else:
no feature reports, no GET_REPORT or SET_REPORT. On Linux the browsers
find keys by that usage page among the `hidraw` nodes and speak CTAPHID
to them directly. A uhid device with that descriptor, whose hidraw node
the session user can open, is a security key to them.

The raw-HID path for controllers (0014) already creates uhid devices
through ghostseat and relays their reports, but its rules don't fit:
gdp-spec.md §8.6 says a client forwards game controllers only, "never
keyboards, mice or security keys", its policy accepts only drivers that
make gamepads, and its descriptor screen is there because the client's
descriptor is untrusted.

A key is also unlike a controller in what it grants. Whoever can open
its hidraw node can ask it to sign in to any site, for as long as it is
plugged in; the key's user-presence test (a touch) is the only gate, and
the key can't show which site is asking.

## Decision

Security keys get their own capability, `security-key` (gdp-spec.md
§8.7), independent of `gamepad` and `hid`, with their own two slots and
messages. The client sends the key's name, vendor and product IDs and
release number, never a report descriptor: ghostseat creates every key
with the same fixed FIDO descriptor (64-byte input and output reports,
no report IDs), with a `phys` of `ghost/uid-<uid>/key<n>` and bus USB.
`hid-generic` must bind, and must create no input device; ghostseat
destroys the device otherwise. ghostseat relays only 64-byte input
reports from wraith and output reports back, and answers any GET_REPORT
or SET_REPORT with an error itself. The existing udev rule already keeps
the hidraw node off seat0 and out of `uaccess` (whose tag systemd's
`60-fido-id.rules` adds), and the existing udev monitor chowns it to the
session's user.

The client forwards only USB HID devices with the FIDO usage page and
64-byte reports, only with its user's consent (a setting, off by
default), and SHOULD show its user which site each request names: the
CTAP2 requests that need a touch carry the relying party's ID in clear.

## Consequences

- A key at the client works with every FIDO client on the host that
  reaches keys through hidraw, browsers included, with no ghost code on
  the host beyond ghostseat and wraith.
- No descriptor from the client reaches the kernel, so there is no
  descriptor screen to get wrong, and the only driver that can bind is
  `hid-generic`. The host learns the key's vendor, product and name, not
  its serial number.
- Origin binding is unchanged: the browser on the host computes the
  origin, as for a key plugged in there. A PIN typed on the host reaches
  the key encrypted (CTAP2's PIN protocol), so the relay never sees it.
- While a key is forwarded, any process of the session's user can ask it
  for an assertion for any site, and a touch grants it. The client's
  notice of the relying party, and the setting being off by default, are
  the mitigation. What it can't do is maintain the key: the client passes
  only the commands a sign-in uses and answers the rest itself
  (`authenticatorReset`, PIN setting, credential management, enrolment,
  configuration, vendor commands) with `CTAP2_ERR_OPERATION_DENIED`, so
  no touch, misplaced or coaxed, can wipe or lock the key. A browser's
  security-key settings page in the session therefore fails on a
  forwarded key; the key is managed on the client's own machine.
- Only the FIDO interface goes through. A YubiKey's OTP keyboard and its
  CCID smartcard (PIV, OpenPGP) don't; smartcards forward over PC/SC,
  separately ([0017](0017-smart-cards-forward-over-pcsc.md)).
- Clients on Linux (Wisp included) and macOS can forward keys as they
  are. Windows (since 10 1903) lets only elevated processes open FIDO
  HID devices, so spectre there needs a helper: a service the installer
  adds, running as LocalSystem, that opens the keys and relays their
  packets to spectre over a named pipe only spectre and the session's
  user may connect to. The wire and the host don't change, and spectre
  stays unelevated; the client gains one privileged component. That the
  helper's access coexists with Windows' own WebAuthn service is
  unverified. The browser client can't forward a key at all: WebHID
  blocks the FIDO usage page.

## Rejected alternatives

- **Forward keys as raw controllers under `hid`.** Takes the client's
  descriptor and needs `hid-generic` on the allowlist, which the
  controller path then extends to any device the client describes. Ties
  keys to the `gamepad` capability and its slots, and blurs the
  consent: controllers are forwarded without asking.
- **Take the client's descriptor, screened to the FIDO page.** Every
  key in use reports the same descriptor, so the client's adds nothing
  but parser surface; a key with a different one is better refused.
- **A virtual authenticator on the host that relays CTAP messages
  rather than HID reports.** Needs its own HID device anyway (that is
  how the host's browsers find keys), and the client would still be
  speaking CTAPHID to the real key, so it is the same relay with a
  reassembly layer added.
- **On Windows, translating the host's CTAP requests into
  `webauthn.dll` calls** instead of the elevated helper. Windows shows
  its own dialog for every request, it wants the client data the host's
  browser has already hashed, and CTAP's PIN and credential management
  have no WebAuthn equivalent.
- **On Windows, running spectre elevated.** Works, but puts the whole
  client, its network code included, above the user for the sake of
  one device.
- **USB/IP passthrough of the whole key.** Gives the host every
  interface, OTP keyboard included, needs `vhci-hcd` and root on the
  client, and is what the reserved `usb` capability may one day be for.
