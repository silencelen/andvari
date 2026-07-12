# Cut 4 — "Email this invite" (owner dev-note) — threat-model + fork — 2026-07-12

> Owner dev-note (ROADMAP §Onboarding & reach): an opt-in "email this invite" checkbox on the Admin
> invite form that ALSO emails the invitee their enroll link (`composeEnrollLink` — the same link the
> QR encodes), instead of the admin hand-delivering the token. **Pitch-until-ratified: no build
> without the owner signing the mail-surface tradeoff.** This doc lays out the tradeoff + a fork.

## What it costs to build (M–L — NOT a UI tweak)

andvari has **ZERO mail infra today** (grep-confirmed; invites are deliberately hand-delivered
out-of-band). "Email this invite" needs net-new server capability:
- an SMTP client + connection config + a credential in `andvari.env` (or an API-based sender);
- an email template rendered server-side;
- a client→server flag on `createInvite` (`AdminService.kt:32`) + the web checkbox (`InviteForm`);
- ops: an SMTP relay/account the CT122 server can reach (the server is on VLAN 2, default-deny —
  outbound SMTP/submission needs a firewall path + a sender identity that won't land in spam).

## The security tradeoff (sharpened by cut 2's finding)

The invite token is a **BEARER CREDENTIAL**. Cut 2's breaker established (and cut 1 encoded) that the
"printed-sheet fingerprint" enrollment step does **NOT** bind a token holder — the fingerprint is
`policy.recoveryFingerprint`, served *unauthenticated*; a token holder can seal their own escrow to
the public recovery key and register with their own master password. So **the invite token is the
credential, and the TTL is its sole containment** (`AdminService.kt:37`).

Emailing the enroll link therefore puts a **bearer credential into an inbox + the mail provider's
hands** (and any inbox-scanning/forwarding along the way). That is a real widening of today's
out-of-band delivery (R3-adjacent). The dev-note's original mitigation ("enrollment still requires
the printed sheet, so an emailed link alone can't enroll") is **WEAKER than it reads** — per the cut-2
finding the sheet is not a control over a token holder. The genuine mitigations are:
- the attacker must still **reach the private enroll origin** (tailnet/LAN) to `register` — an emailed
  link embeds that origin, and public register is refused; so a random inbox-thief off the tailnet
  can't complete it (bounds, doesn't remove, the threat);
- a **short TTL** on emailed invites (the token is only live briefly);
- **default-OFF** (secure-by-default; hand-delivery stays the norm).

## The fork (owner decides — three honest options)

**A. Build it, hardened (M–L).** Email the enroll link, but: default-OFF checkbox; emailed invites get
a FORCED short TTL (reuse cut-1's "Invite expires in" — pin emailed → 1 hour, non-extendable);
**private-origin-only** (no emailing from the public break-glass origin); the form states plainly that
the emailed link is a time-limited key. Owner signs off on the net-new SMTP surface + a mail account/
relay CT122 can use. *Cost: the SMTP capability + a mail-surface review; the biggest of the 4 cuts.*

**B. Notify-only, NO token in the email (S–M — the security-preserving middle).** Email the invitee a
**heads-up with no token** ("You've been invited to andvari — ask <admin> for your one-time code and
your printed recovery sheet"), and keep the token itself hand-delivered. This gets the "andvari sent
me something" convenience **without** putting a bearer credential in an inbox — the token never
transits mail. Still needs the SMTP capability, but the mail-surface threat is far smaller (no
credential at risk). *This is my recommended default: most of the convenience, little of the risk.*

**C. Don't build it — keep hand-delivery.** For a small household over a trusted tailnet, hand-
delivering the token (in person / a secure channel) is simple and leaks nothing to a mail provider.
The invite-unify (cut 1) already made minting + handing over a token fast. *Zero new surface.*

**Recommendation:** **B (notify-only)** if the owner wants the email convenience — it's the honest
sweet spot given the token is a bearer credential. **A** only if the owner specifically wants the
token itself emailed and accepts the (bounded) inbox exposure with the short-TTL + private-origin
hardening. **C** if email isn't worth any new server surface. All three need the owner's call on the
SMTP capability before any build.

## RATIFIED 2026-07-12: Option A (email the token, hardened), relayed via the owner's M365 tenant

Owner ratified "email the token, hardened" and noted the household **Microsoft 365 tenant** as the
relay (jacob@ is global admin; `monahanhosting.com` lives in the tenant with SPF/DKIM). That solves
deliverability + removes self-hosting a relay: the server sends via **M365 SMTP submission**
(`smtp.office365.com:587`, STARTTLS, AUTH) from a dedicated no-reply `@monahanhosting.com` mailbox.

### Wire — the SERVER composes + sends (option (b)); the client only flips a flag
The token is minted BY `createInvite`, so the client can't compose the enroll link before the call —
and we do NOT want the server emailing a client-supplied URL under andvari's from-identity. So:
- `AdminService.createInvite(email, isAdmin, ttlMinutes, sendEmail: Boolean)` — when `sendEmail` and
  email is configured, after minting the token the SERVER composes the enroll link from a configured
  base + the token + email and sends it.
- **Server-side enroll-link codec** = a Kotlin twin of web `composeEnrollLink` (`enrolllink.ts`):
  `<base>/enroll#<base64url(JSON{v,o,t,e})>` — **vector-pinned against the TS encoder** (a golden
  link vector both must reproduce; the web `enrollPrefillFor` decoder is the consumer, so the format
  must match byte-for-byte). This is the one cross-impl seam — pin it.
- `ANDVARI_INVITE_BASE_URL` (the PRIVATE origin the link embeds, e.g. the tailnet URL) is server
  config; emailed invites are thus structurally private-origin-only (the link only resolves on the
  tailnet/LAN, and public register is refused regardless).

### Hardening (all server-enforced, not just client copy)
- **Feature-flag on config presence:** no SMTP config (host/user/pass/from) OR no
  `ANDVARI_INVITE_BASE_URL` ⇒ `emailConfigured=false` ⇒ the client checkbox is **disabled** and a
  `sendEmail=true` request is a **no-op** (the invite still mints; the email just doesn't send) — never
  a hard error that loses the invite.
- **Forced short TTL for emailed invites:** when `sendEmail`, the server clamps the invite TTL to
  ≤ `QR_INVITE_TTL_MINUTES`-equivalent (60 min) regardless of the client's `ttlMinutes` — the emailed
  token is a bearer credential in an inbox, so its window is the short one, non-extendable.
- **Default-OFF checkbox**, private-origin-gated in `InviteForm` (`isPrivateOrigin`), with copy: "Also
  email <addr> a sign-in link. The link is a one-time key — it expires in an hour; still hand over the
  printed recovery sheet in person."
- **No secret in logs:** the audit/log for `invite_email_sent` records userId + the recipient's
  presence, NEVER the token or the composed link (extends the existing audit-PII discipline).
- **Recipient is server-known:** the email goes to the invite's own `email` (never a client-supplied
  recipient) — no open-relay / arbitrary-recipient vector.

### Server SMTP impl
- Add a mail dependency (jakarta.mail / angus-mail) to `:server` (a real new dep — call it out) OR a
  minimal STARTTLS+AUTH client; an `EmailSender` interface with an `SmtpEmailSender` reading
  `andvari.env` (`ANDVARI_SMTP_{HOST,PORT,USER,PASS,FROM}`). STARTTLS required; fail-closed on a TLS
  or auth error (log, don't leak). Send is best-effort + OFF the request path (a mail hiccup must not
  fail the invite mint).
- **Graph API alternative (future / if SMTP AUTH is unavailable):** M365 is deprecating basic SMTP
  AUTH; a Graph `sendMail` client-credentials sender (an app registration with `Mail.Send`, scoped by
  ApplicationAccessPolicy to the no-reply mailbox) is the durable path — same `EmailSender` interface,
  swappable. Note for 3b/ops; SMTP first for least code.

### Web
- A default-OFF checkbox in `InviteForm` beside `isAdmin`, shown only when `isPrivateOrigin` AND the
  server reports `emailConfigured` (from admin status / policy); passes `sendEmail` on `adminInvite`.
  The result view is unchanged (the token/QR still show; the email is an *additional* delivery).

### Owner OPS (cut 4 is INERT until these — ships flag-off)
1. A dedicated **no-reply@monahanhosting.com** (or similar) M365 mailbox with **SMTP AUTH enabled**
   (Exchange admin; + an app password if the mailbox has MFA). *(Or set up the Graph app registration.)*
2. A **VLAN-2 outbound firewall path** from CT122 → `smtp.office365.com:587` (UDM default-deny blocks it).
3. Put `ANDVARI_SMTP_*` + `ANDVARI_INVITE_BASE_URL` in `/etc/andvari/andvari.env`; restart andvari.
4. Send a test invite to yourself; confirm delivery + that the link enrolls on the tailnet.

### Ship
Server jar change → snapshot + vzdump → `ops/deploy.sh` → byte-verify jar boot + web bundle →
CHANGELOG (owner-voice, "off by default until you configure email") → push → Telegram.

## Breaker findings (2026-07-12) — BINDING (verdict: NOT ready to build as first-drafted; fold ALL)

The mail-surface breaker found the ZK posture SOUND (the token is a bearer credential, not a vault
secret; the link carries no key material) but the outbound-mail plumbing needs real hardening:

- **B1 (BLOCKER — spam cannon):** the admin-typed `email` reaches SMTP with ZERO validation
  (`AdminService.kt:32-43` does only `email_taken` + `.lowercase()`; the web `type=email` is
  cosmetic + curl-bypassable). A CRLF/`,`/`;` in the address injects headers (Bcc) → andvari relays
  spam as `monahanhosting.com`. FIX: strict single-address validation **at `createInvite`, before
  the address is ever stored** (reject CR, LF, NUL, comma, semicolon, whitespace, angle brackets,
  >1 address); use a mail API that rejects malformed addresses and NEVER build headers by string
  concatenation. (The "recipient is server-known" claim was false — it's stored-first free text.)
- **B2 (BLOCKER — 100% DOA):** `enrollPrefillFor` requires `payload.o === location.origin` EXACTLY
  (`enrolllink.ts:264`), and `compose` doesn't canonicalize. A trailing slash / explicit `:443` /
  uppercase / a different reaching-origin → every emailed link silently falls through to manual
  entry. FIX: at boot, require `ANDVARI_INVITE_BASE_URL` to match a canonical browser origin
  (`ORIGIN_RE`: scheme+host[:non-default-port], lowercase, no path/slash/userinfo) AND run a
  `compose→parse→assert(o===base)` self-test; on failure `emailConfigured=false` (never mint DOA).
- **A1:** REUSE `core.client.EnrollLink.compose(base, token, email.lowercase())` (already the
  vector-pinned twin — `:server` depends on `:core`); do NOT write a third impl. `null` return
  (ill-formed UTF-16) ⇒ skip the email, keep the minted invite.
- **A2:** the forced ≤60 min clamp applies to the FINAL ttl (after the null→72h default resolves):
  `if (sendEmail) ttlMs = min(ttlMs, 60*60_000L)` — not to the nullable input.
- **A3:** compose+send AFTER tx commit, dispatched fire-and-forget to `Dispatchers.IO` with bounded
  SMTP connect/read timeouts (SQLite is single-writer — a blocking send in the tx stalls all writes;
  on the route coroutine it ties up a Netty worker). `createInvite` returns the token regardless.
- **A4:** no secret on ANY log path — `invite_email_sent` meta = the token-hash prefix (never the
  address/link); on failure log only an error class/boolean (jakarta `SendFailedException` carries
  the recipient); mail-library debug OFF (it dumps `RCPT TO` + `DATA` = recipient + link to Loki).
- **A5:** enforce private-origin server-side — disable email (`emailConfigured=false`) if the
  base-URL host matches `config.publicHostname` (reuse `Auth.kt:88 isPublicOrigin`), else the
  "structurally private-origin-only" claim is false.
- **A6:** rate-bound invite creation — `/admin/users` has NO `limiter.allow` today (`App.kt:580`)
  unlike every sharing route; add a per-recipient + global send cap (reuse `RateLimiter`) and record
  the M365 ceiling (~30 msg/min, 10k/day) as a hard limit, or an abuse loop damages the real domain.
- **A7:** amend `spec/05-threat-model.md` — R8 (a bearer invite credential now transits M365 + rests
  in an inbox; bounded by ≤60 min + private-origin + public-register-refused) AND widen T1 (a CT122
  compromise now also gains send-as-`monahanhosting.com` + a new internet egress via the stored
  `ANDVARI_SMTP_PASS`).
- **A8:** STARTTLS **required** + cert-validated (`mail.smtp.starttls.enable=true` +
  `starttls.required=true`, NO `ssl.trust=*`) so a MITM on CT122→office365 can't strip TLS and
  harvest the M365 AUTH credential.
- **NITs:** `emailConfigured` requires ALL of {host,user,pass,from,base}; `InviteRequest.sendEmail:
  Boolean = false` (older clients never trigger mail); one line of admin help re multi-origin DOA;
  SSRF — base URL is embedded not fetched (accepted), SMTP host is owner-set config (accepted).

**Full doctrine to ship:** the above folded → build → find→refute review → gated → snapshot+vzdump
→ deploy (flag-OFF; inert until the owner's OPS above) → byte-verify → push → Telegram.
