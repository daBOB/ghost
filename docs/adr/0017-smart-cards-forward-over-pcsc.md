# 0017. Smart cards forward over PC/SC, with writes by consent

Status: Accepted (2026-10-19)

## Context

ADR 0015 forwards a security key's FIDO interface only, and left smart
cards (PIV and OpenPGP, a YubiKey's CCID interface) as a separate
decision. They are what OpenSC, GnuPG, `ssh -I`, browsers signing in with
certificates, and `ykman` use. A card can be reached at three levels:
USB (a virtual CCID device), PC/SC (the reader API every platform has),
or the APDUs themselves.

A card is not a security key. It asks nothing of its user: whoever has
its PIN signs and decrypts, and a PIN typed in the session is the
session's. Some of its commands write: new keys, certificates, PIN
changes, a reset. On a PIV card left with its factory management key,
replacing a key needs no PIN at all. ADR 0016's answer for keys, that
the client reads each request and asks its user about writes, fits here
better still, since the client can read every APDU.

## Decision

Smart cards forward over PC/SC, as the `smartcard` capability
(gdp-spec.md §8.8), separate from `security-key`:

- **The client speaks PC/SC.** spectre lists readers and talks to cards
  through the platform's own PC/SC (pcsc-lite, PCSC.framework, WinSCard),
  one API on all three, so Windows needs no helper. Up to two readers
  are forwarded, readers the host presents excepted.
- **The host runs a pcscd per session.** wraith holds a socket in the
  user's runtime directory, starts pcsc-lite's `pcscd` on its first
  connection (socket-activated: pcscd ignores `PCSCLITE_CSOCK_NAME` for
  its own end), with USB scanning off (`PCSCLITE_HP_DROPDIR` pointed at
  nothing) and polkit off (the socket is the user's), and puts the
  socket in the desktop's `PCSCLITE_CSOCK_NAME`, and in the user
  manager's for what systemd starts (gpg-agent, so scdaemon); `wraith
  --session-ended`, which wraith.service runs however wraith stops, takes
  that back. The session sees only the client's readers, never the
  host's, and no other user's.
- **A small reader driver relays.** `host/ifd-ghost` is a pcsc-lite IFD
  handler, one entry in pcscd's reader configuration per forwarded
  reader, whose device is a Unix socket wraith serves. wraith answers
  presence from what the client last said, so pcscd's polling never
  crosses the network, and relays power and APDUs to the client.
- **Readers keep the client's names.** `ykman` knows a YubiKey by its
  reader's name. pcscd reads its configuration only as it starts (it
  rescans USB on a signal, not its reader files), so wraith restarts it
  when the readers change, and keeps a reader's entry, empty, while the
  same client may come back.
- **Exclusive, or shared in transactions.** spectre opens a card
  exclusively while the host has it powered. Desktops often have a
  program holding every card shared (a Chromium-based app, on the
  machine this was built on), so spectre then shares it and puts the
  host's commands in a PC/SC transaction that lasts until the host has
  been idle for 2 s (Windows resets a card idle in a transaction for
  5 s). Each new transaction first selects again the applet the host
  last selected, since another program may have moved the card in
  between. Powering down, or the slot ending, resets the card.
- **The client's policy** (`libgdp`'s `CardPolicy`) follows the selected
  applet and classifies each command: PIV's and OpenPGP's signing,
  decrypting, authenticating and reading pass; their writes are asked
  about, one command at a time, with ADR 0016's prompt rules and its
  fatigue limit and switch (`spectre -u` refuses keys' maintenance and
  cards' writes alike); everything it can't read is refused. A command
  chain is asked about by its first block. Since PC/SC waits for each
  APDU's answer, the host simply waits while the user is asked.
- **Always refused**, whatever the settings: a YubiKey's management
  applet (it turns the key's interfaces off), OATH (every code that
  needs no touch), OTP and HSM Auth; the FIDO applet, whose CTAP would
  go around ADR 0016; GlobalPlatform's security domains; any prefix of
  those AIDs, since a card may select an applet by part of its AID;
  logical channels other than 0, which the policy doesn't follow, and
  secure messaging, which it can't read.
- **Unknown cards** (a national ID, a CAC) pass unread only by a client
  setting (`spectre -y`), off by default.

## Consequences

- The session's PKCS#11, GnuPG, `ssh -I` and `ykman` use the client's
  cards. Measured over loopback, `ykman piv info` takes 0.2 s; each APDU
  costs a round trip, so first use over a WAN takes seconds (17 APDUs
  for `pkcs11-tool -L`, about 60 for `ykman piv info`).
- A PIN crosses the session's encryption in clear inside a `VERIFY`, and
  the session sees it, as with a reader on the host. Neither end logs
  APDU data.
- A session can still sign with a card whose PIN it has, and can lock a
  PIN with wrong guesses, as a program on the host could. A touch-policy
  slot adds a physical check to each use.
- In shared mode another program's state on the card (its selected
  applet, a verified PIN) is lost when the host's transaction re-selects,
  and a host's verified PIN may be lost after it idles: OpenSC verifies
  again from its cache; others may ask for the PIN again.
- `ykman` through the session can't read the YubiKey's device info or
  change its interfaces; it falls back to what the PIV and OpenPGP
  applets say.
- GnuPG on the host must use PC/SC rather than its own CCID driver:
  `disable-ccid` and `pcsc-shared` in `scdaemon.conf`.
- The host needs pcscd installed (packages recommend it); without it, or
  without the driver, wraith doesn't offer `smartcard`.
- Not done: Veil's browser client (WebUSB blocks the smart card class),
  readers with PIN pads, and contactless pseudo-APDUs (`CLA FF`).

## Rejected alternatives

- **pcscd's socket protocol in wraith**, as xrdp does. That protocol is
  internal to pcsc-lite and changes between versions.
- **A virtual USB CCID device for the system pcscd.** polkit refuses
  remote sessions the system pcscd, and one pcscd shows every user's
  readers to every other user.
- **pcscd as a systemd user service**, as first planned. It works, but
  wraith would need systemd to restart it whenever the readers change,
  and ghostseat to set the environment before the session starts and
  clear it after; wraith running pcscd as its child ties both to the
  session, and systemd stops it with wraith's unit.
- **Exclusive access only.** On a desktop with a browser open the card
  was always held shared, so forwarding would fail until the user found
  and closed the program.
- **Pass everything, with a generic warning.** Neither end could then
  say what a write does, and a session could switch a YubiKey's
  interfaces off or read its OATH codes.
