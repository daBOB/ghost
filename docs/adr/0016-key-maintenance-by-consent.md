# 0016. A forwarded key's maintenance passes with its user's consent

Status: Accepted (2026-10-19)

## Context

ADR 0015 forwards a security key's FIDO interface and, after its
security review, has the client refuse every maintenance command:
`authenticatorReset`, PIN setting and changing, credential management,
bio enrolment and configuration. The review's finding was that a
compromised session could reset a key or set a PIN on it with the
user's touch, because the touch is the only gate and the key can't say
what the touch approves: a reset looks like a sign-in.

The refusal costs features. A browser's security-key settings page
fails on a forwarded key, and ADR 0015 says the key "is managed on the
client's own machine". A Wisp thin client has no other machine, so its
users can't manage their keys at all.

The client reads every request in clear before passing it on, so it
can say what a request would do. The key can't.

## Decision

The client passes a maintenance request only once its user approves it
in a prompt the client draws (gdp-spec.md §8.7), one request at a time:

- **What is asked about.** Setting and changing the PIN; a reset;
  listing, deleting and renaming passkeys; enrolling, removing,
  renaming and listing fingerprints; turning on enterprise attestation,
  always-require-verification, and a longer minimum PIN length.
- **What stays refused.** What the client can't describe: vendor CTAP2
  commands, `authenticatorConfig`'s `vendorPrototype`, unknown
  subcommands, and vendor CTAPHID commands (over which a YubiKey turns
  its applications and interfaces on and off, and some keys take
  firmware).
- **Reset only in its window.** Keys accept a reset only within about
  ten seconds of power-up. The client asks only within ten seconds of
  opening the key and refuses later resets unasked, so a session can
  ask only right after the user replugs the key, which is also how a
  browser's own reset flow goes.
- **Grouped where one request is many.** One approval covers a
  passkey listing (metadata, then a begin and a next per site and per
  credential) while its commands keep coming at most a minute apart,
  and an enrolment's samples and naming after its start. Deleting is
  asked about each time, naming the site and account when the key
  listed them earlier: the key's listing replies pass through the
  client unencrypted.
- **The prompt's rules.** It is drawn by spectre and holds the input
  (`client/spectre/src/ui/notices.hpp`): the words are the client's, never
  the host's; Deny is the default; Allow takes a click or its key and
  not Enter, and neither in its first second; unanswered, it denies.
  While a request waits, the client sends keep-alives, so the host's
  FIDO client waits as it would for a touch, and a CANCEL withdraws
  the prompt.
- **Off switches.** A client setting, and a per-thin-client Veil
  setting, refuse all maintenance unasked, as before this ADR. After
  three refusals in one connection the client stops asking until the
  next.

## Consequences

- Keys can be managed from the session: a browser's settings page works
  on a forwarded key, and Wisp users can manage theirs.
- The review's finding is answered by an informed approval rather than
  a blind touch. A session that talks its user into approving can still
  reset or lock a key; the fatigue limit, the reset window and the
  switches narrow that, and nothing removes it.
- A PIN being set travels encrypted between the host's FIDO client and
  the key, so the client can't check it; its prompt says to allow it
  only if the user typed the PIN themselves.
- The host and the wire are unchanged. A client that keeps refusing
  everything still conforms.
- The policy now holds state between requests (held messages, the
  listing and enrolment grants, the names from listings), and reads the
  key's replies as well as the host's requests.

## Rejected alternatives

- **Keep refusing.** Leaves Wisp users unable to manage their keys, for
  a risk the prompt addresses.
- **Prompt once per CTAP 2.1 token permission** (`cm`, `be`, `acfg`)
  and let the key enforce the rest. Keys speaking the 2.1 preview
  commands (older YubiKey 5 firmware) accept a legacy token for them, and
  reset and PIN setting use no token at all.
- **Pass vendor commands with a generic prompt.** The client can't say
  what they do, so the user can't make the decision the prompt asks
  for.
