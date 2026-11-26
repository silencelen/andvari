# andvari spec 05 — threat model

## Assets
A1 vault plaintext (credentials, TOTP seeds, notes, attachments). A2 master
passwords. A3 UVKs/VKs/identity keys. A4 an instance recovery seed (private instances that
offer operator recovery). A5 account availability (lockout = losing access to everything). A6
metadata (who has how many items, sizes, timing, who connected with whom). A7 the at-rest
quick-unlock secret — the on-device artifact that, combined with a live unlocking factor, opens a
vault without the master password. Two variants with **different at-rest posture**:
**A7-android** (the Keystore-wrapped UVK blob + its non-exportable hardware key, spec 01 §8.1) is
*durable* but *hardware-gated*; **A7-extension** (the PIN-wrapped, session-scoped UVK blob
double-wrapped under a non-extractable WebCrypto co-key, spec 01 §8.4) is *non-durable*
(browser-session-scoped, dies at browser exit) but *hardware-less*. A8 the trust records: pinned
instance cards, contact pins, the account's vault records and genesis, and the operator's signing
key, which signs the instance card.

## Adversaries & guarantees

Adversaries named by the onboarding and trust design: **T1** the server (on an instance someone
runs, that person is T1); **L** the link channel (reads, replaces or races a link or QR on its way
between people); **E** a mailbox (reads the recipient's mail, or controls the sending tenant); **A**
an abuser (creates many accounts, floods codes, fills the cap); **M** a member colluding with T1;
**D** a device (T3/T4).

**Goals.** G1 no trust decision rests on a value only the server vouches for: a person's key is
pinned only from a link that person's own app made, or from a device the account already trusts.
G2 only a vault's owner can change who holds its key; every membership, role, ownership and lifecycle
change is signed by the account that made it, and an M+T1 coalition can forge none of them. G3 two
people verify each other once, and the result reaches every device either of them links. G4 nobody is
asked a question they cannot answer (no raw fingerprints, no "which vault is personal"). G5
withholding and forking by T1 are detected where a device holds enough history to tell, and fail safe
everywhere else. G6 the public instance admits strangers without a third-party CAPTCHA, bounds the
damage they can do, and never reveals whether an email address has an account. G7 the operator's
power over members is exactly what spec 03 §7 and §18.6 list, plus whatever T1 already has; an
**honest** operator's every use of it is audited and emailed to the member, which is transparency for
an honest operator, not a control against a hostile one (the operator is the host and can suppress
both).

| # | Adversary | Outcome (by design) |
|---|---|---|
| T1 | **Server compromise (root on the instance host)** — reads DB, blobs, memory, logs. On an instance someone runs for the public, that person is T1. | Sees only spec 02 §5 plaintext + traffic patterns. No item content, no keys, no master passwords (authKey is one-way; verifier re-hashed). CAN: serve stale data, drop writes, swap ciphertexts *between* slots — blocked by AD binding; roll back the DB — mitigated by client caches noticing rev regression (clients warn, never delete local newer state); withhold, delay, replay, reorder and fork what it serves (R20, R21); register accounts of its own. CANNOT: forge a signed log entry, card, genesis, link offer or answer; pin its own key into anyone's contacts; make a device adopt a vault key that fails the genesis commitment. CAN corrupt/deny service → availability handled by offline caches + the operator's backups. **What the records tell of a typed address** (2026-11-18; spec 03 §14.1): every record the server keeps of a typed address, other than an account's own address and a queued mail's recipient, is the address's keyed hash under a key derived from the instance's own secret, so rows of one address still tie together, and whoever reads the audit page, the system's journal, the logs or a copy of the database (a backup, T7) and guesses an address confirms nothing, of people with no account either; T1, who can read the environment file that holds the secret, can. A refusal by a limit leaves one record per address, device or account per period (spec 03 §8), so such a reader learns that an address or a device was locked for a while and when, and, for an address with an account, which account, but not how many tries were refused. **What a hostile server can do to availability, said and not changed (2026-11-17):** (a) it can name a password-hashing cost at the top of the clients' limits (10 passes over 1 GiB, spec 01 §7) in its policy; a device then derives at that cost at a recovery and at every later unlock. That costs time and memory, discloses nothing, and is what the limits are for. (b) The question by which a device link stops before anything is committed on a device that keeps another account (design §8.2) cannot compare the account's identity key before the pickup, because the link's bundle does not carry it in the clear; so an address that this device knows bound to the same account under another key is refused only afterwards, when the session reaches the part that keeps sessions. Only a hostile server can produce that case; the link is then spent and the session it opened is ended alone (spec 01 §7). (c) A recovery on a device that keeps no copy of the account makes its new wrap at the cost the server serves, so a hostile server can hold that account at the floor; the floor is the least any client takes (accepted on 2026-11-17, spec 01 §7). **What it can no longer do (2026-11-17):** serve an account's key texts (the salt, the wrapped account key, the sealed identity seed, the personal vault's wrap) in a non-canonical spelling: they are taken only in canonical form and anything else is refused before it is stored, so a server cannot have a healthy copy judged damaged and talk the person into removing it; and serve another identity under the right account key for a device to take over its copy: a take is held to the identity the device knows (spec 01 §7). **What it gains from a forgetting it talked a person into** (rules of 2026-11-17; design §4.4): after "Forget the earlier account on this device", the device takes the next account served under that address as on a new device, so the server may serve any other account there; the same account id under another key is not among them (rules of 2026-11-19): the offer is made only where the server serves another account than the one the address is tied to, never where it serves the same account under another key or an account whose key the device keeps under another key, and the forgetting keeps the record of the earlier account's identity key, so a server that first shows another account to obtain a forgetting and then serves the old account under a key of its own is refused at that second step. The record kept is the account's id and identity key, as a record of the server's: that account is refused here under any other key, under any address at that server, for as long as the server is not forgotten; "Forget this server" removes these records, so a device that then pins the same server again knows those accounts no more. **The rule for an account tied elsewhere** (rules of 2026-11-19 to 2026-11-21, design §3.11; kept in the shared code since 2026-11-21, and for the identity record at "Forget this server" since 2026-11-19): where one account id is known at two addresses on a device (a server that moved and whose move was not followed, or one that serves a copy of another's accounts), an end at one server (a sign-out, a confirmed deletion, "Forget this server", the forgetting of an earlier account) is that server's word alone: what is held for the account at the other server stays (its copy with what waits in it unsent, its marks against an older state, its records kept per server), and the records kept by the account's id alone, its identity record among them, go only where nothing at another server ties the account, read once before anything is removed. A tie is an address record there naming the account, or one that cannot be read; a record there kept under the account's id; or a record there for the same address, unless that server's own address record for the address names another account, and, for a device's row, only where it holds a device id (a row that only records a sign-in attempt ties nothing) or cannot be read as one; a store that cannot list its records ties. So neither server can make the device forget what the other serves, and a server the device forgot (by "Forget this server", or with a confirmed deletion that forgot it) is a first sight behind the trust gate when it is met again. Before 2026-11-21 a confirmed deletion or a forgetting at one removed them for the other, whose next read was then a first sight, where it could be served an older state once without being caught and another key for that account without the record that would refuse it. **What the tie leaves behind** (a limit, 2026-11-21): where the tie keeps a record it no longer needs, the deleted account's records stay on the device, most of them readable without the account's keys (its identity key, the stored state's marks, the vault logs' hashes, the recovery mirror, the escrow mark); in the states known (design §3.11) this is a damaged store or a rare sequence, not an everyday state. Since 2026-11-21 the phone and the desktop app (the shared code's app engine) remove them once the device knows the account nowhere (R48); they stay where that removal is held back, and in `andvari-cli`, which has no such removal (R46). One such state found on 2026-11-19: the same address used at two servers left an identity record behind after both servers were forgotten, which refused only that account under another key; by reading, the removal of 2026-11-21 takes it at the second "Forget this server" (not yet shown by a test of that state). The command-line tool's own deletion and forgetting of an earlier account do not read the tie yet (R46). So a server that shows another account under a known address can, with the person's two taps on the offer's two sentences, make the device forget the tie and the copy, and cannot make it take any account it knows under another key. Where a device link stops before its pickup on a device that holds a record of the link's account's key, the device cannot tell a key substitution from a mistaken forgetting: it offers nothing there, and a sign-in with the password decides. A sign-in's late answer that races another refusal raises no offer (a retry gets it; accepted). A confirmed deletion of an account removes everything of its server on the device only where nothing of another account is kept there, and a kept identity key of an earlier account counts as something kept, so the server and that record stay (without that, the account taken in the earlier one's place, once deleted, would take the kept key with the server, and the earlier account could then be served under another key). Forgetting an account after a deletion of unknown outcome keeps the device's records of the address's account and of its key: the same account served later under another key is refused, and another account under the address gets the offer to forget it. Under a policy that keeps the account's keys at the server, the unlock that asks the server for the keys holds them to the device's record of the account's identity key and to the address's record, and the same account under another key is refused there as the identity fault. (Rules of 2026-11-19; the shared code and the web client keep them since that day, spec 01 §7; in both a forgotten account's key record also survives the confirmed deletion of the account taken in its place (the browser because it never forgets the server at a deletion).) **The extension** (rules of 2026-11-19, spec 01 §7; kept since 2026-11-19, before which it kept no record of an identity key or of an address's account and took both substitutions at a fresh sign-in without a word): it keeps, per server, which account each address is and each account's identity key; a password sign-in, its one-time-code step and the quick unlock refuse the same account under another key, and a sign-in refuses another account under a known address. The quick unlock (PIN, biometrics) compares the served identity key with the kept record as the password sign-in does, so a server that holds an account's vault key (a party that delivered a recovery holds it) cannot open that account there under a key of its own. The key's record keeps the verified key in one fixed form and keys are compared as decoded bytes, so the server that serves an account at its first sign-in in a browser does not choose the stored encoding and cannot later get the true key refused there; any value under a record's name counts as a record, and one that is not a record (a null included) refuses that account as the identity fault until "Forget this server" (denial only). When the extension cannot read what it remembers of a server, it takes nothing and writes nothing; a browser with no store cannot choose a server at all. A record is written only where none exists. These records outlive every sign-out, lock and "Remove data for this server"; "Forget this server" removes them with everything else of that server, and after it the extension takes whatever card, account and key that server serves next. **The extension's "Forget the earlier account on this device"** (rules of 2026-11-19, spec 01 §7; kept since 2026-11-19) is offered only at a password or one-time-code sign-in refused because another account was served under a known address, never for the same account under another key, at a quick unlock, or where the records could not be read. It removes, at that server only, the record tying the address to the earlier account and that account's own records (item homes, cached personal wrap, account-state memory, the device record, its quick unlock), and keeps the record of the earlier account's identity key and everything of the server, so that account served later under another key is still refused, with no offer. Only the person can forget, from the extension's own popup: the second step is taken only from a press that began at least one second after the confirmation stood (or a click with no press whose own time is that late), so repeated or doubled clicks and held keys cannot pass it; nothing is sent to the server by the forgetting. The offer lasts only until the next sign-in attempt, lock, server switch or worker stop; after that a new sign-in brings back the refusal, and the offer with it. The notice that the extension now remembers the new account is kept at rest, with the server's records, until it is said; "Forget this server" and "Remove data for this server" remove it. An account forgotten by mistake and served again under its own key is taken as itself; its account-state memory starts again, so a server can serve it an older account state once without being caught (as in every client). A login the person asked to save while the extension was locked is saved into whichever account is signed in next, a newly taken account included; the confirmation says so. A sign-in refused for an identity reason ends at the server the session it was given (at its own address, with the pin in force, and never an open session of that account); one refused because the records could not be read does not, and that session lapses or is ended by the next sign-in on the same device row; each refusal of another account under a known address leaves one signed-out row for that account at an honest server; nothing of a refused sign-in's session is kept in the browser. The first password sign-in after the update, where no record exists yet, is trust on first use: it is taken as on a new browser. A server can always produce "another account under this address"; after a forgetting the device trusts whatever new account the server next serves there. It gains no token, no key and no waiting change of the forgotten account, provided nothing of that account is left on the device, which is why the forgetting removes every store of it. The second confirmation says that forgetting means trusting whatever the server serves under that address. What it cannot gain from one: the forgetting is only ever the person's act, after the second confirmation, and no answer of a server, no flow, no link, no timer and no start of the app calls it; it sends nothing, so the server learns of it only from what the device does next; it leaves what the device knows of the server (its card and its pin), so a forgetting never makes the device accept another server; it is judged by the account's id, so an account the device keeps (open or locked, at another address of the same server after a followed move, under another address, or held as the server's operator) loses nothing and keeps its identity record, and a server cannot use a forgetting to weaken the check of an account the device still keeps; and while a flow for that address is under way it removes nothing. A hostile server can keep such a hold alive until the person cancels the flow (a kept request for the operator's help with a far end, a link poll answered "nothing yet", a two-step code asked for again), which only refuses the forgetting meanwhile (accepted on 2026-11-18). A forgetting at an old address of an account while a flow under its new address runs gives the same result as a forgetting just before that flow, which is harmless because that account is not kept (accepted on 2026-11-18). The app deletes everything it holds for the forgotten account at that server (its own store and its mirror among them) without condition, whatever the device kept of its session, so that a server which later serves the same account id under another key finds nothing to reuse (design §4.4). **A refusal it can produce at will:** a server can answer an account deletion with a log that moved on at any time, and so can any signed-in member of a shared vault by leaving a leaf out; the device's budgets are given back for it, so an honest person is not made to wait by it; the account's ceiling for deletions, drawn before the password is judged, never is, so a member who produces it cannot keep the server's hashing permits busy and make everyone's sign-in wait (spec 03 §13). The server keeps the deletion's give-back and its ceiling since 2026-11-18. The web client keeps the narrowed offer and the kept key record since 2026-11-19, and both apps draw the shared code's offer since 2026-11-19. The shared code no longer offers the forgetting for the same account under another key on any road, and its forgetting keeps the key's record (since 2026-11-19, closing that day's gap). **Not kept yet (2026-11-18):** the shared code leaves the forgotten account's own store and its mirror for the app to delete, which the app does only when the forgetting removed a kept copy (2026-11-18). |
| T2 | **Passive network (anything between a client and its instance)** | TLS everywhere: the operator's front terminates it (the bundled caddy with HTTP-01 or DNS-01, a tunnel, `tailscale serve`, or the operator's own proxy — `docs/self-hosting.md`), and `ANDVARI_FORCE_HSTS=1` is mandatory whenever the origin is https (`andvari setup` sets it). The origin grammar (spec 01 §5.1) admits plain http only for `localhost` and `127.0.0.1`, for development; no client stores, dials or shows any other plain-http origin, and test mode refuses every non-loopback origin. |
| T3 | **Stolen/lost device, locked** | At-rest cache is ciphertext (the native offline cache persists only §5-table ciphertext + metadata in SQLite, and the **web client persists the same set in per-account IndexedDB inside the browser profile** — spec 02 §8/§8.1; keys only in memory or hardware-wrapped quick-unlock per spec 01 §8). Offline unlock accepts the master password current at last online contact; **remote device revocation / password change take effect only at next connectivity, and what they end there is the session, not the copy** (design §4.4 "A session the server ends does not delete the device's copy"; spec 03 §2, a refused refresh). Per client: the **apps on the shared engine** (Android, desktop) drop the tokens, the quick-unlock key and the keys in memory, and keep the copy, its queue of unsent changes and the account, which opens read-only with the master password the copy is wrapped under until the person signs in again, signs out or forgets the server; the **web client** with the offline copy on does the same (it keeps no quick-unlock material), and without it signs out; the **extension** drops its tokens and its quick-unlock record and keeps what the session holds, readable, until its next lock (it keeps no copy across a lock); the **iPhone app**, still on the older client code, deletes its cache, its cached accountKeys and its quick-unlock material. Local data remains ciphertext without the master password; a stolen locked device with a known-old master password can read the last-synced cached vault: on the iPhone until it reconnects, on the engine apps and the web for as long as the copy stays on the device — an accepted narrowing in exchange for offline availability, and so that no single answer of a server deletes changes not yet sent. The Devices screen says it: revoking a lost device stops it syncing and does not wipe it. Web deltas (spec 02 §8.1): the browser profile cannot be excluded from OS backup, so OS backups may carry the ciphertext DB (⊆ T7); the Unlock screen discloses an existing copy ("Offline copy on this device — last synced <t>") so a borrowed-machine user can see and remove it. **Durable-cache consent:** **web** persists at rest only after an explicit per-device opt-in, default OFF. **Desktop** likewise asks per device, default OFF; until the desktop user answers yes, or whenever the origin forbids the cache, its access+refresh tokens live in memory for the run (where they ARE written, the file is sealed under the operating system's key store; what that protects and what it does not: "Desktop kept sign-in" below). **Android stays policy-driven default-ON — the exemption justified on the record:** installing an APK on one's own phone *is* the device-consent act, and the cache is at-rest encrypted, gated by the hardware quick-unlock co-key (A7-android), bounded by the 7-day staleness ceiling, protected by the KDF cache-read floor (T8), and purged on policy-`false`. In every case `offlineCacheAllowed=false` remains a forbid + wipe of that origin's own namespace (R11). **A save with files that is kept to be finished later** (spec 03 §5) stays with its set-aside files on the device under that account's own name at that server, sealed with that account's own check, until its item has landed or it is given up; a record that is not that account's is removed, never used. Another account signed in on the same device never loads, sends or shows it, and nothing of it travels on another account's session. It goes with the copy at a sign-out, a forgetting of the server, an account deletion and a policy that forbids the copy; a session the server ended removes nothing of it, by design, so that the next sign-in finishes it. |
| T4 | **Stolen device, UNLOCKED with vault open** | Out of scope: an open vault is an open vault. The window is bounded by the inactivity auto-lock (`autoLockSeconds`, enforced by all three clients incl. the Android autofill path — spec 01 §8 "Auto-lock") + policy clipboard clearing. Both timers are clamped on the client: effective auto-lock ∈ `[floor, 900 s]` and clipboard-clear ∈ `[1 s, 300 s]` — a server-supplied 0/absent/oversized value clamps into range (spec 03 §1.1). **A recovery kit on show** (rules of 2026-11-17; spec 01 §7, design §10) is a secret on the screen of a device nobody may be watching: a lock, by hand or by the idle limit, wipes it on every road, a kit shown with a refusal that came after a commit included, and a kit screen with no account open has its own idle limit (five minutes without a touch or a key, warned thirty seconds before). The person is told afterwards that the kit is gone and that the next sign-in shows a new one. The app interface wipes such a kit at every lock and keeps the notice until it is dismissed, and the browser's kit screens warn before their limit acts (2026-11-18). **Every kit on an app's screen** (rules of 2026-11-18; design §10) takes its limit and its warning from the shared code, is under the lock clock on every road (the print screen, the autofill road, visible without the focus, through the phone's sleep), keeps the phone's screen on up to its limit, offers no Copy or Cut in the fields it is typed into, and leaves nothing to print or on the clipboard after a lock. Since 2026-11-18 the Android app draws the notice that a kit is gone, locks a kit that came on show while it was away before it is drawn, keeps the lock clock on the print and autofill roads and while visible without the focus, keeps the screen on, and offers no Copy or Cut from the menu or a keyboard there. Since 2026-11-19 the shared code hands every kit its limit and its warning; on Android a lock empties what a kit's screens draw from, also while the app is away, a kit left for the print screen is covered with a clock that counts sleep, and an accessibility service cannot copy or cut from a kit's fields; the desktop app draws the notice, takes every kit's limit and warning from the kit, signals the warning to the operating system once, and after a lock leaves nothing to print and nothing it put on the clipboard. Since 2026-11-19 an unlock from Android's autofill window makes no kit (the app locks first where a kit is due when its own window comes on show), and a kit made in Settings runs from the kit's own limit. Since 2026-11-19 both apps tell the shared code when nothing of them is on show without a lock (on the desktop: the window minimised or hidden), and at the return a lock that fell due comes first, so a kit made while the app was away and wiped unseen is said as never shown. **What no app can keep from a kit on show** (known limits, 2026-11-18): while a computer sleeps a kit on show stays in memory, and hibernation writes memory to disk; an operating system's session lock without sleep is not noticed by the desktop app (the kit's own limit applies); text on the screen is readable by assistive technology and by anything that uses its interface; once a page has gone to the printer, the spooler's own timing is the system's, and a system's "Print to PDF" dialog left open after a lock stays on the screen, though it can save nothing of the kit; on Android, what the toolkit's own drawn nodes still hold until the first redraw after the return cannot be reached by the app, and whether a keyboard's own editing panel can copy from the fields a kit is typed into is up to the keyboard. |
| T5 | **Malware on a client device** | Out of scope (keylogger gets the master password). This is the boundary every password manager shares. |
| T6 | **Malicious/compromised web origin** (server serving hostile JS) | Accepted gap of the web client: page-load-time trust. Mitigations: CSP `default-src 'self'`, immutable versioned bundles, no third-party origins, no CDN; native apps are the trust anchor. High-value operations never run in the web client. **The web client binds no identities** (spec 03 §15.9): it does not create, show, open or answer links, scan or display identity QRs, run or approve device links, sign instance cards, process link answers, or sign in as the operator account; those code paths are compiled out of the bundle and a source pin test enforces it. It may still recover its own account with the recovery kit, typed or pasted, from "Forgot your master password?" only (the kit was shown to this same web client at sign-up, so this exposes nothing new to its server), and cancel (veto) a recovery request for its own account. It pins the card chain of the one origin that serves it (spec 01 §5.3), so it notices a fork or a rollback on a later visit; it cannot follow a move. So a hostile bundle cannot learn a link secret and put its own key into *another* person's contacts. It still holds the user's UVK and can write account state (a planted contact, a wrong vault record): native devices ask before using a contact made elsewhere (R35). The durable web cache (spec 02 §8.1) sharpens T6's **timing**, not its ceiling: hostile same-origin script can exfiltrate persistent ciphertext + the wrapped accountKeys from a LOCKED/idle tab — an offline-cracking surface, floored by T8's KDF math and client-enforced at cache read — where previously it had to wait for the next unlock, which still hands hostile JS the master password itself. |
| T7 | **Backup theft** (the operator's snapshots, and any offsite copy of them) | Backups contain only what T1 sees (ciphertext + metadata). Neutralized by design. |
| T8 | **DB leak → offline cracking** | authKey verifier is argon2id-hashed server-side; vault security rests on Argon2id(master password) at ≥64 MiB — weak master passwords remain the user's risk (policy enforces minimum strength at enrollment). The client offline caches (native SQLite / web IndexedDB, spec 02 §8/§8.1) widen **where** this sentence applies — a stolen device, a browser-profile leak, or an OS backup of one is the same offline-cracking surface as a server DB leak — not its math: the identical H1 floor is enforced server-side, client-side at every unlock, and at cache READ (a cached sub-floor `kdfParams` payload refuses offline unlock outright). **Pattern-aware strength estimate:** the estimator collapses a repeated block (charged once, `period + 1`) and a ±1 run (charged 2) before the length term — spec 07 §2.3 `effectiveLength`, vector-pinned. Deliberately asymmetric: the **enrollment / change-password floor still scores the pre-collapse proxy**. The residual is unchanged and owned by the user: a weak-but-non-repetitive master password is still accepted, and this row's Argon2id cost is what stands behind it. The recovery kit's secret is generated (256 bits) and never typed into a KDF, so a leaked `recoveryVerifier` is not crackable (spec 01 §2.1). |
| T9 | **Recovery-sheet thief** (private instances with operator recovery) | Holds A4 ⇒ can decrypt every escrowed UVK of an operator-posture account **given the sealed blobs** (needs server data too), and act as those accounts (R3). Physical security of the two sheets + USB is the control; the annual drill verifies presence. Compromise response: a new recovery key with a signed rotation (spec 04 §5), every opted-in device re-seals, the old blobs are replaced with no copy retained and with `secure_delete` and a WAL truncate (spec 04 §3). Residual: backups taken before the rotation still hold the old blobs and must be rotated out. The sheet's seed also signs rotations and assisted-recovery payloads, so its thief can sign a rotation to a key of their own; opted-in devices follow a signed rotation, which is why the seed lives only offline. No public instance holds such a sheet under variant R. |
| T10 | **Malicious server substituting a recovery key** | The escrow anchor is the **pinned card's `recoveryFp`** — from the baked root, a link offer, or the operator's own setup — at full length, never a typed sheet and never a served value alone (spec 04 §2). A key change without a rotation signed by the old seed reaches opted-in people only as a warning that defaults to turning operator recovery off, and the first-consent walk shows the same warning to anyone opting in afterwards. The weak case is a typed-address or enrol pin made on a server that was already hostile (R22). The kit is symmetric (no public key) and T10-immune by construction; the public instance has no escrow under variant R. |
| T11 | **User enumeration / credential stuffing** | Deterministic fake prelogin salts, uniform 401s, per-IP rate limits, and **email-keyed exponential backoff on LOGIN and device-link pickup** (5 consecutive failures → `2^(n-5)` s capped 900 s, applied **uniformly to existing and unknown emails** so throttling is not an account oracle; the backoff state is keyed on a SHA-256 of the normalised email, and an email over 254 characters is refused `400 invalid_email` BEFORE any lookup). Sign-up and recovery requests answer uniformly (`202`) whether or not the address has an account; `link_required` is answered only after the password and any code verified. There is no email lookup route. **Password-before-second-factor oracle:** for an enrolled account a correct password without a code answers `401 totp_required` and a wrong one the uniform 401, so an attacker holding the email can confirm the master password without a code — bounded by the per-IP 5/min and the email backoff (the missing-code branch counts as a failure). **Accepted residual:** the `totp_required` signal itself — every client renders the code field off it; removing it means always asking for a code. `/recovery/self/*` deliberately keeps **per-IP fixed-window only, NO per-account backoff** (never lock a victim out of last-resort recovery; the 256-bit recovery secret makes per-IP sufficient). |
| T12 | **Link channel** (L) | Whoever reads a link or QR first can answer or claim it first. **Controls:** single use (the first answer or claim wins, and the real recipient then sees "already used"); the creator fingerprint `F` in the fragment (an interceptor cannot swap in its own offer); creator-side expiry; the committed comparison code (spec 01 §5.5), compared by typing, in person or on a call, and required before any vault is shared through a link; for device links, the committed code typed on the existing device plus the master password before any session; for device links, the new device acts only on a link opened from its own "Link from your other device" screen, and pins the link's origin before it claims, so the password goes only to an origin it pinned (spec 01 §5.3). **Residual:** a remote connect link sent over a compromised channel, whose codes the two people never compare, pins the wrong person. Such a contact is `compared = false`: it cannot receive vaults automatically, and the UI says it is unconfirmed. |
| T13 | **Sign-up abuse** (A) | Mass accounts, code floods, cap exhaustion. Controlled, in the order they bite, by per-IP and per-address limits, the daily account maximum, the cap (which bounds the total damage), the operator closing sign-up with one switch, an optional proof of work, an optional domain blocklist, and per-recipient email caps (spec 03 §14). **Residual:** an attacker can fill the remaining cap slots, which the operator answers by disabling the junk accounts (disabled accounts free their slot) or closing sign-up. |
| T14 | **Mail** (E) | The mailbox holds only sign-up and recovery-request codes and notices, and beside a recovery-request code its mailbox value, which opens nothing but one more request for the same address (R37), never secrets or acting links (spec 03 §14.5). A compromised sending tenant can phish as the product (DMARC, plus "we never send links that sign you in" on the website). A recipient's mailbox can complete a sign-up for that address, which is the address owner's own risk. The sending app registration has send-only access, scoped to one mailbox. |

## Accepted risks (signed off by owner at hardening gate)
R1 JVM/JS cannot guarantee secret zeroization (GC copies) — industry-standard gap.
R2 Web client page-load trust (T6).
**R3 Operator recovery holder.** Applies only to operator-posture accounts on private instances,
which chose it after the warning (spec 04 §2). For them the operator, or anyone holding the recovery
sheet and a copy of the server's data, can do more than decrypt: the escrow yields the identity seed,
so they can **act as the member**, sign as them, and read every shared vault the member belongs to;
once opened, the keys never change (R33). On the public instance under variant R, R3 does not apply
at all.
R4 Server metadata visibility (A6) — includes a residual prelogin oracle: after a KDF-policy change,
an account whose stored params differ from the current default answers prelogin with diverged params
(existence confirmed) until it re-keys via password change; unknown emails always answer the current
default params. The same residual has a second channel (LOW, accepted): a real account's salt and
params CHANGE on password change or re-key, a fake salt never does, so an observer polling prelogin
over time can tell the two apart; the per-IP 10/min bucket bounds the polling. Same class (LOW,
accepted): a former member of a shared vault who kept an attachment id can learn from the upload route
whether that file still exists (spec 03 §9, audited as `attachment_cross_vault`).
R5 Single server per instance — availability comes from offline-first clients plus the operator's own
backups, never from HA.
R6 TOTP seeds co-located with passwords (accepted eggs-in-one-basket, user decision).
**R7 No VK rotation.** A removed shared-vault member who kept the key, working with the server, can
still **read and write** later items: items carry no author signature, and a hostile server accepts
writes it should refuse. The remove dialog says so and offers "Move everything to a new vault" (spec 02
§10.8), the app-level rotation until P6. Vault deletion removes the server's copies after a 7-day grace
but is NOT cryptographic erasure toward ex-members, and the operator's backups keep copies until their
own retention expires; an ex-owner after a hand-over keeps the key likewise.
**R8** (server-composed invites) is retired: the server composes no invite and mails no link
(spec 03 §14.5).
**R9 The recovery kit.** The kit's secret wraps the account's own UVK, so possession of the kit (with
the email address) is UVK-equivalent **for that one account**. Two faces: (1) **LOSS** — an account
without operator recovery (every account on the public instance) that loses **both** master password
and kit has **no way back**: if a device is still unlocked, export and start a new account; otherwise
the data is gone (accepted; the sign-up copy says so). (2) **THEFT** — whoever holds the kit can reset
that one account against an honest server. Controls: custody of the printed kit; the online reset is
gated by the phase-1 **verifier**, the **per-IP rate-limit** (no per-account backoff, so no targeted
lockout), and the **single-use replay-bound ticket** (spec 03 §12); the commit revokes every session,
replaces the kit and emails the person, so a stolen kit used against an honest server is visible and
cannot be reused. A kit is accepted only on the kit-recovery screen, which names the account and
server, so a kit handed over as an "invite" cannot walk someone into an account its maker controls. The
recovery unlock **preserves the identity-pubkey hard-fail** (spec 01 §5).
**R10 Hostile endpoint.** Any client may be pointed at any server, including a hostile one. What holds
the line: (1) **the policy-trust boundary** (spec 03 §1.1) — a hostile server may make a client safer,
never laxer (R11); (2) **the instance card and the password rule** (spec 01 §5.2–§5.3) — a client sends
a value derived from an account's secrets only to the origin of a session it holds for that account,
or to an origin with a password pin (baked, or confirmed through the Trust Gate, or a kit or setup pin
for its own account), and the Trust Gate names the origin and the operator key; (3) **origin-clean
switching** — a server change drops access+refresh tokens before the first request to the new origin,
native/extension data is namespaced by origin and account, and one app talks to one instance at a time;
(4) **blast radius** — creating an account on a hostile server exposes what the user gives THAT server:
a new vault there and one account's metadata, provided the master password is unique, which is why the
gate's copy says to use a master password used nowhere else. Every policy probe is tagged with its
origin and a generation counter, bounded in time, and cancelled on an origin change, so a hostile
origin the user abandoned cannot answer late and decide the home origin's policy.
**Quick-unlock clock residuals (Android — accepted).** (a) When `Settings.Global.BOOT_COUNT` is
unavailable, "same boot" falls back to the clock-derived reference (`wall − elapsedRealtime`), which a
stepped-back clock can still make look like a reboot; the always-on monotonic belt and `now < stamp`
failing closed still hold. (b) Across a genuine reboot the cross-boot branch trusts the server anchor:
a device powered off for more than 30 days whose clock was stepped back BEFORE its last boot can still
pass, provided the origin's last server-attested time fell within the window of the stamp. Closing
either needs a trusted clock on the device; the master password remains one tap away in every case.
**R11 (policy monotonicity — forbid-only fields and clamped timers).** Clients treat
`offlineCacheAllowed` as **forbid-only**: `false` ⇒ prohibition + prompt wipe of the declaring
origin's own namespace (never another origin's), which stays unconditional. **Changes that wait to be
sent** (decided on 2026-11-17, spec 03 §1.1): the client first tries ONCE to send them, then wipes as
specified, whatever the attempt brought, and afterwards says how many could not be sent. Once means one
run through what waits, each request with its ordinary limit, no second try, no waiting for a
connection to come back, no question to the person; the run ends at the first request that gets no
answer, and a session that has ended sends nothing, so the wipe then follows at once. The attempt
uses only the copy's own account's session, has one limit of sixty seconds for the whole, runs once
per copy under one lock with every other wipe, and counts three outcomes (sent, may or may not have
arrived, not sent); a wipe that could not be made is never said as made and is tried again only
while the policy still forbids the copy (rules of 2026-11-17, spec 03 §1.1). A change the server
answers with a conflict counts by what the server did with it (rule of 2026-11-18). On a device
(rules of 2026-11-18, design §4.4) nothing is removed before it is counted, a kept policy record that
cannot be read deletes nothing, and the account's wrapped keys at rest go with the copy, so that
without the server there is no unlock. Logins the Android app has caught and not yet answered stay
sealed on the phone under such a policy (decided on 2026-11-18), which is safe only because such a
login cannot be opened on the phone without an unlock that the server answers; where that does not
hold, the decision is not built. Under such a policy the device keeps none of the account's wrapped
keys, its salt, its sealed identity seed or the quick-unlock key, on any road that takes a session (an
unlock, a sign-in, a recovery, the operator's help, a device link's pickup; a refresh writes no keys),
and a record marked as having its keys at the server is stripped of any wrap when it is written at
rest (rules of 2026-11-19); a caught login stays sealed to the account's identity key, and opening it
needs the identity seed, which then comes only from the server, and the master password. **A session
that ends while the account is open** leaves in memory exactly what the device keeps at rest, as a
lock does (kept in the shared code since 2026-11-20): at every end, the server's (a refused renewal,
or the live channel's word that the device was revoked) and this device's own (it could not confirm
the session and no try is left), no wrapped key of the account stays, the lock screen says that the
keys are at the server and that the server ended the session, and with the server silent a right and
a wrong password are both answered that the session ended; nothing opens, and no caught login opens
or is said as saved, until an unlock the server answers after a new sign-in; a restart changes
nothing. Shown by tests for the end by the live channel's word, by a refused renewal and by no try
left, with the policy recorded before the opening and while open, logins caught before and after the
end, and a restart; by reading only for the policy recorded while open together with a refused
renewal or with no try left. **Fixed on 2026-11-20:** until then a session that ended while the
account was open under such a policy left the keys the server served in the app's memory, so that
until the app was started again the master password opened the account, and a login caught after the
end, with the server silent; it needed the master password. Two states still keep served keys in the
keeper's memory (2026-11-20): an account held as its server's operator (every unlock refuses it before
any key is touched) and the record a sign-in call that was left puts back; no sequence is known in
which either opens anything without the server, and each is to be made what is kept at rest. An
answer with the status of "not signed in" from anything in front of the server starts a renewal, and
where an earlier renewal was cut off more than a minute before, the session then ends as one this
device could not confirm (said, not changed). **Who can still guess the master password under such a policy**
(rules of 2026-11-19): the account's wrapped keys leave the device when the policy is recorded and
every unlock asks the server for them, so whoever holds the device with its session can ask the
server for the wrapped key and guess the master password away from the device for as long as that
session lives (each try sends nothing derived from the password). A session has no end of its own:
its access token lives an hour (the operator's policy) and each refresh gives a refresh token that
lives thirty days from then, with no limit on the chain's age, so a device that refreshes at least
once a month keeps the road open until the session is ended. The session ends at once when the
account's owner removes the device from another device, when the password is changed on another
device (every other session of the account ends), when an operator disables the account or removes
the device, and when the account is deleted; a sign-out ends only the signing-out device's own
sessions, there is no sign-out of every device, and an operator's enable does not revive ended
sessions. Removing the device ends that device's road only: whoever knows the master password signs
in again as a new device, unless the account requires a link. What such a policy adds is that the
server can end the session, which stops every further fetch at once (the very next call is
refused), but a wrapped key already fetched stays open to guessing away from the server for good; a
password change does not close it, because it re-wraps the same account key, so the old wrap still
opens the account to whoever guesses the old password (R33). Without the server nothing on
the device can be guessed against, and nothing is wiped or lost while the server cannot be reached
(decided on 2026-11-19: no unlock and no wipe then; the one try and the wipe at the first unlock the
server answers). **Whoever holds a device's live session can fetch the account's wrapped keys with
one call and then try master passwords without the server** (spec 03 §3): that is true of every
client that signs in, with or without a policy; the route's read limit does not bound it, and only
ending the session ends that road for every further fetch (a wrap already fetched stays open to
guessing, above). **An older wrapped key** (a limit, 2026-11-19, left open on
purpose): under such a policy a server that serves an OLDER wrapped key makes an older master
password work on the device, and nothing is said; a device that keeps its own wrapped key would
refuse it, and a new device accepts it today. It is one face of R33 (no account re-key): the
wrapped key carries no generation the device can check against a record it keeps (the account's
state document is protected against an older state; the wrapped key is not). A copy of the
device's storage taken before the policy was read still holds the wrapped key and its salt; with
the master password it opens everything caught before and after, offline.
**What the count says, and its limits** (2026-11-19): a request that may have left is never said as
"never left". **"Never left" is the transport's word**, given only for a failure of the connect
itself with no earlier attempt attached: a connection refused, no route to host, a timeout while
connecting, or a name that did not resolve (five failure classes, looked for along the failure's
causes), and never where the failure carries an earlier attempt, as a second try of a request whose
first attempt was written does; none of the five is thrown after a byte of the request was written
(established for the JVM's client and Android's as built, not for every version of their libraries,
and for a real Android device and the iPhone by reading only), so a renewal that left the device is
never sent a third time or after its minute.
The session keeper and the policy's one attempt take that word as it is, and no failure that can
also come after bytes were written is added to it. So in the other direction a secure connection
that fails while it is being set up, a proxy that refuses its tunnel, and an unreachable network
that the platform reports as a plain socket failure (as the JVM's own sockets do) are said as "sent,
no answer came" although nothing left, because the same word decides whether a refresh may be tried
again (R41); on Android an unreachable network is reported as a failed connect, so there it is "never
left", as "no route to host" is everywhere. On an iPhone
the transport never says that a request did not leave, so there an unreachable server's changes read
as "may or may not have arrived" (an edit stopped before it was queued is said as not made since
2026-11-19). The web client keeps the attempt since 2026-11-18, and judges a conflict by what the
server did since 2026-11-19; the shared code keeps the count, the attempt and what is said since
2026-11-19, and since 2026-11-19 also the keys' leaving and the unlock that asks the server, on every
road (no road walked, and none read, opened a caught login without an unlock the server answers,
except a session that ended while the account was open, fixed on 2026-11-20 as above; a
password change answered after a lock leaves no key material at rest; the race in which a pending wrap
is written into a stripped record is covered by the strip by reading only), the caught logins kept
sealed and sent once after a removal, the kept saves finished by the attempt, the number of
unfinished moves, and both apps draw the notice (spec 03 §1.1). Also kept since 2026-11-19: the
shared code's answer to the apps whether a removal is still owed, which the desktop reads instead of
its disk; both apps' lines for keys kept at the server (with the server stopped nothing the phone's
screens offer opens a caught login); and the attempt at an opening that records a newly forbidding
policy does not send a change beside a request already out: it counts that request's changes by its
answer and gives them its one try only where that request got no answer (spec 03 §1.1). `true` is **necessary but never sufficient** —
at-rest persistence additionally requires per-device consent on web and desktop (Android's default-ON
exemption is on the record in T3), so a hostile `offlineCacheAllowed=true` alone can never switch a
device to durable storage. Oversized or absent `autoLockSeconds`/`clipboardClearSeconds` clamp into
the client-side ceilings (T4). `kdfParams` floors — including the cache-read sub-floor (T8) — remain
the backstop that makes even a consent-granted cache non-catastrophic under a weak-params-planting
server. A monotonicity test suite asserts a hostile policy object can never leave any client laxer than
its floors/ceilings.
**R12 (online guessing with TOTP optional).** `totpRequired` is per instance, default false, so online
password guessing is resisted by: the flat per-IP login limit (`ANDVARI_LOGIN_RATE_PER_MIN`, default
5/min, spec 03 §8), the email-keyed exponential backoff (5 consecutive failures → `2^(n-5)` s capped
900 s, uniform across existing and unknown emails, reset on success), and the score ≥ 3
master-password floor at enrollment (T8's own estimator, spec 07 §2.3). Enrolled TOTP is verified on
every login. Residual: distributed low-rate guessing below both rate keys — bounded by the
password-strength floor.
**A wrong secret on any route is refused and recorded, and does nothing else that can be turned
against the account's owner (rules of 2026-11-16 and 2026-11-17; spec 03 §2, §8 and §18.2).** (a) A
two-step code tried on a signed-in session counts on a back-off of its own, with the proofs' curve,
which refuses only the checking of codes; the routes' per-minute buckets alone let a stolen session
try thousands of codes a day. That back-off and the proofs' back-off are kept per device, not per
account: kept per account, a session held without the password could keep the account's counter at
its cap with about a hundred requests a day, and the owner, on any device, was then refused every
action that asks for the password again. Per device, a stolen session still has only its own 109
guesses a day of each, and the owner's other devices are not touched. (b) Turning two-step sign-in
off, replacing its secret on an account that has one, and setting it up at all (also right after a
sign-in) need the master-password proof, checked before the code is looked at, so a session in the
wrong hands can neither remove the second factor by guessing codes nor add a factor of its own. (c) The code that verifies an
operator-assisted recovery request has a rate bucket per caller address, and each wrong code leaves
an audit row that names the account only when the request is real, so that a decoy answers exactly as
a real request does. (d) The sign-in back-off per address stays: anyone who knows an address can make
its sign-ins wait, and a signed-in session is not affected; an exemption for a device the account
already knows is a possible later improvement, not built. A stranger using up an applicant's sign-up
codes stays as well: the daily cap bounds it, and it touches no account. (e) The rate buckets of the
routes that need a session are kept per device too, with a ceiling per account of four times the
device's limit (rule of 2026-11-17, spec 03 §0.1), so a session held without the password spends only
its own device's budget and cannot keep the owner from any route on another device; spec 03 §8 says
what such a session can still do. The server keeps (a), (b), (c) and (e) since 2026-11-17. The
released 0.29 line, and
0.30.0, which is cut as it is (decided on 2026-11-16: the fix goes on the new line only), have the
weakness (b) closes: there a session alone can turn two-step sign-in off with a guessed code.
**R13 (unanchored assisted recovery).** An assisted recovery (spec 04 §7) is anchored by the person's
account ID, which must come from outside the server (the kit, a notice older than the request, a
co-member). When no anchor exists, `recovery-cli assist --no-identity-anchor` runs after a typed
acknowledgment: it still refuses a copy that names another address than the one the operator typed,
but cannot detect a wholesale server-minted identity that claims the person's address. Every device that
unlocked the account before refuses the forged identity at the next unlock (spec 01 §5 self-identity
backstop, kept per user id and per typed address: the web client and the shared code each bind the
address typed at an origin to the user id and identity key of the first account opened for it, so a
minted account under a new user id meets a mismatch, never a fresh pin); an account with no such
device has no backstop. (The temporary-password form of this row is retired with the temporary password.)
**R14 (account state).** The account-state blob (contacts, vault records, accepted vaults, the recovery
record) is UVK-sealed, so the server alone cannot add to it, but it can withhold it or roll it back;
each device keeps a high-water mark of the in-blob `seq` and its own sealed copy and refuses the
rollback, but a device that never held a newer copy cannot tell. The shared code reads the blob again
only when the sync's counter (`accountStateSeq`, spec 03 §4) says another device wrote it; a server
that lies about that counter can make a device read less often or more often, which is withholding
again, never make it accept a record it did not open. Every record only ever refuses (a
missing record never blocks anything), so a rollback fails safe. Pins are pairwise: a family of N
people connects per pair, and there are no introductions (no transitive trust). Whoever holds the UVK
can write the blob (R35).
**R15** (signed grants in the compatibility window) and **R16** (removal proofs) are retired with the
clean break: grants are bound to the signed log (spec 01 §6.3), and removals are signed log entries.
**R20 Withholding.** T1 can delay or hide new log entries, card updates, link answers and account-state
tombstones. Devices detect it only against a head or checkpoint they hold, and otherwise see stale but
genuine state. Every case fails safe: nothing unsigned is accepted. A hostile server can also store a
far-future `at` in a vault log and so freeze offers on that vault (denial of service).
**R21 Equivocation.** T1 can show different members different genuine prefixes of a log, or race two
genuine entries at one position. A device that sees both freezes the vault; a device that sees only one
cannot tell. Partly detected: the account's own vault records (spec 02 §9) and item-carried log heads
(spec 02 §3). An item head only makes a device fetch and, if nothing new comes, note it in the vault's
details and mark the member list "may be incomplete"; it never freezes the vault on its own, so a server
that keeps serving one consistent branch is not caught by items alone. No cross-member gossip beyond
items exists. A withheld later `add` makes the shown member list **understate** the audience.
**R22 Trust on first use.** A hand-typed self-hosted origin pins whatever card it serves first. So does
the link's origin on a new device that links to a private instance, and a link-offer origin that someone
signs in to. Each passes the Trust Gate, which names the origin; for a device link the existing device
shows its address beside the QR, and the bundle must agree afterwards. Invites (for creating accounts)
and setup links avoid the gate. **Residual:** a person who confirms the gate for an address that is not
their server's gives that server their `authKey`. A pin made on a server that was already hostile cannot
detect a recovery key that server named from card 0 (spec 04 §2).
**R23 Password-only devices.** The one-tap contacts list (spec 02 §9) trusts the account-state copy the
server serves. The server alone can hide contacts or restore a removed one, never add one. A holder of
the UVK can add one (R35), and the copy says so. Linking from another device avoids it.
**R24 Web client and extension.** A web user's own vault remains T6-exposed; identity binding is
unavailable there by construction. The Chrome and Firefox extension verifies the card and the genesis
but not vault logs (spec 01 §6.5). It relies on UVK wraps that full clients minted after their own
checks, opens a shared wrap only for a vault the account accepted, and never writes to a shared vault.
So a log anomaly that only a full client would catch does not stop the extension from **reading** that
vault until a full client acts on it, a hostile server can keep a shared vault readable there after the
person was removed, and after a re-add a replayed old wrap can still open there (it cannot check
`addSeq`). It cannot plant a key, move the personal vault, or get a shared-vault write out of it. A
hostile web bundle can also write contacts into account state; native devices ask before using any
contact made elsewhere.
**R25 Connection metadata.** Who connected with whom, and when, is visible to the server (links and
connections rows), as vault membership topology already was (the vault log is in the clear). The log
rows of a purged vault are kept a year after the purge.
**R26 Cap denial.** Covered by T13.
**R27 Assisted recovery** (operator-posture accounts on private instances; the public instance only
under variant K). A request needs the emailed code; 7 days without a veto from any of the account's
signed-in devices; the person reading a request code to the operator over a channel the operator trusts;
and a payload signed by the offline recovery key. **Residuals:** an attacker who holds the victim's inbox
**and** passes the operator's identity check, while the victim has no signed-in device to veto, gets the
account (the copy names this). Since 2026-11-16 the recovery copy
names its account's address inside the account's own signature, the operator types the address of the
person they help and the offline tool compares, and the answer names the address and the person's device
compares it with the one they typed: another account's copy, or an answer for another address, is
refused. Without an account ID from the kit, or from a notice older than the request (no mail sent
because of an assisted recovery carries one, spec 03 §14.5), the identity check is unanchored (R13). Repeated requests can pester a victim within the email cap; the emailed code
allows 5 tries per request, and requests are capped at 5 per address per window of 24 hours, so at
most 25 tries a window (no per-address cap on tries: it let a stranger use up the owner's; R37); the
mailbox's holder, who reads the code anyway, can open up to five more requests a window with a
mailbox value (spec 03 §18.1); the route also
has a bucket per caller address and an audit row for each wrong code (R12 (c)). **These checks bind an honest server only:** a
server that is itself the attacker can open a request with its own key, mark it verified and its hold
passed, suppress the bell and the mail, give the operator its own contact details, and pose as the
person; an honest operator who believes it then seals the person's UVK to it. Only the operator's own
check, through a channel they already had, stops this: natural on a family server, absent for
strangers. No small fix exists. On a fresh install pinned by typed address such a server can also
answer the person's own request itself with a minted account that claims their address: it gets an
account whose keys it holds, not the person's vault. The full list of what these checks do and do not
cover is spec 04 §7, "What these checks do not cover".
**R28 Availability.** The public instance is one server run best-effort, with tested off-site
backups. Offline caches keep vaults readable: an app's copy whenever the app holds one, the web client's only in
a tab already open when the server goes away, because the page itself comes from the server and there
is no offline app shell (spec 02 §8.1, 2026-11-16). "Best effort" is stated plainly on the first screen and on the website.
**R29 Age and region.** Enforced by terms and store distribution, not technically.
**R30 Operator signing key.** Whoever holds the operator's signing key (a stolen operator device, or a
captured operator password with server access) can sign card updates. **Moves:** private-instance
devices follow a move only after a one-tap prompt that shows both origins; store builds never follow a
move of the public instance. **Renames and handovers:** possible. **Recovery:** it cannot redirect
operator recovery **silently**: a rotation needs the offline seed's signature; a card with a new
`recoveryFp` and no such signature reaches every opted-in person as a prompt that defaults to turning
operator recovery off, says the change may mean a takeover, and needs the master password to keep it.
Anyone who keeps it has handed their escrow to the key thief. **New consents** are covered too: the
first-consent walk starts at card 0 for every pin, so anyone opting in after such a card sees the same
warning, except someone whose only pin is an enrol or Trust Gate pin made after the swap (R22). Under
variant R the public instance has no operator recovery to redirect, and its `kind` cannot be changed in
store builds. **Controls:** the operator account is never anyone's everyday account and never signs in
on the web. A phones-only family that keeps the operator account in `andvari-cli` on the server host
accepts that the host can sign moves, renames and an unsigned recovery-key change too. Recovery from a
stolen operator key is `reset-instance-identity` (spec 03 §17.5): a new chain, every device re-pins.
**R31 Address kept for the deletion email.** The `account_deleted` (or `account_deleted_by_operator`)
message keeps the deleted address in `mail_outbox` until it is sent, at most 24 hours (spec 03 §14.5).
This amends R19's "no column holds the address".
**R32 The product origin.** `andvaripass.com` serves the join pages for **every** instance. Its host, CDN
or DNS could serve a scripted page that reads the fragment of every link opened in a browser (when the
app is not installed, or an in-app browser keeps the link), giving the reader `s`, enough to race the
real recipient. It cannot swap the creator's key (`F`), cannot pass a compared code, and cannot get a
session without the master password. Controls: a static host with no scripts and CSP
`script-src 'none'`, separate from any instance; apps that handle links directly; and "Paste a link".
**R33 No account re-key.** The UVK and the identity key never rotate. Someone who captured them
(malware, an operator restore under R3, a stolen unlocked device) keeps them after a master-password
change. The remedy is **start fresh**: a new account, export and import, re-connect, then delete the old
account. The help page "I think my account is compromised" says exactly that.
The same holds for an older master password. A change of the master password re-wraps the same
account key (spec 01 §7). A server that kept an older wrap, together with whoever knows the older
password, can open the account for as long as that key lives. No client rule changes that: a device
takes a served wrap only when it opens to the key the device already holds, and an older wrap does.
The sign-in over a device's kept copy (spec 01 §7, rule of 2026-11-17) works the same way: a sign-in
replaces what the device keeps only when the key it opened is shown to be that account's key as the
device knows it, so a server cannot slip another account's keys under a kept copy; but a server that
kept an older wrap, and a person who types the older password into a sign-in on that device, bring the
older password back on that device. The person is told in one line, after signing in, that the copy
was sealed under another master password than the one typed and now follows the server's. The server
gains nothing it could not do with that password already. A device link on a device that keeps the
account follows the same rule in full. A recovery, with the kit or with the operator's help, cannot:
the password is lost, so no kept wrap opens to be compared, and the recovery replaces the kept and
pending wraps; but the recovered key must still open the kept copy's sealed identity seed to the kept
identity key, so a server cannot slip another account's keys under a kept copy by way of a recovery
either: another key commits nothing and changes nothing kept (rules of 2026-11-17, spec 01 §7). An
answer to a request for the operator's help that names another account than the one the device keeps
for the request's address is refused at the pick-up, before the person is asked anything: whoever holds
the operator's recovery key can make such an answer. For the same account, the part of the shared code
that keeps sessions takes no session whose key is not shown to be the kept account's: a sign-in whose
kept wrap opened to the same key shows it (and the kept seed is then written again from the verified
session, so a damaged copy is repaired); every other flow must open the kept seed. Spec 01 §7 lists,
with their date, the gaps that remain beside these rules (among them a recovery on a device that keeps
another account, which still commits at the server before the device refuses its session, an answer
for another account that passes the pick-up, and a damaged copy refused even at a sign-in with the
right password).
**R34 Key changes of contacts.** A contact whose key changes (reinstall, re-registration) must be
re-confirmed with a matched comparison code. Until then the old key stays pinned and the new one is
untrusted. People will see this after reinstalls; it is the price of not trusting the server's say-so.
**R35 Account-state writers.** Any holder of the account's UVK can write its account state: the
account's own devices, a hostile web bundle while the person uses the web client (T6), and the operator
of an operator-posture account who opened its escrow (R3). Such a writer can plant a contact (native
devices ask before using it), write a vault record that makes every device of the account see that
vault withheld or frozen and read-only (a record ahead of or beside its log, spec 02 §10.4 (e)) or
refuse it (a record of another genesis), or replay an old recovery choice (devices act on it only with their own mirror). It
can already read and change every vault the account holds, so these add denial of service and
confusion, not access; a vault frozen this way is left through copy-out and "Move everything". **Device
links:** because `approveMac` covers `outer` alone (spec 03 §16.6), a UVK holder that also works with the
server can pair the existing device's genuine `outer` with an `inner` of its own; it already owns the
account, and its one gain is that contacts it planted become current on the new device without the
per-device prompt.
**R36 An old address after a move.** An instance that moved leaves its old address in the public
chain. Whoever later controls that address (a lapsed domain, a reused dynamic-DNS or tunnel name) can
serve the genuine chain cut off before the move, and a device that never saw the move still trusts it:
a sign-in there can be relayed, a session token sent there used, and a recovery kit made before the
move accepted there and its proof replayed at the real instance. No client check can tell a cut-off
chain from a current one. Controls: the operator keeps every address the chain has named (the
self-hosting guide says so in its section on moving); apps ask for a new kit after following a move;
store builds never follow a move of the public instance. Not done: refusing kits made before a move at
the server would lock out everyone who had not re-made theirs, and binding the sign-in and recovery
proofs to the address dialed (a signature over a server nonce and the origin, in place of a reusable
key) would remove relaying altogether but replaces the login protocol: a later design.
**R37 A stranger can delay assisted recovery.** The per-address cap on opening recovery requests
(5 per window of 24 hours that starts at the first request it counts, spec 03 §18.1) is what keeps a
mailbox from being flooded with codes, and it counts every request for the address, whoever opens
it. So a stranger who opens five requests for someone's address can delay that person's assisted
recovery by a window at a time: past the cap the owner's own
request is a decoy that sends no code. The stranger learns nothing (every request answers alike,
T11) and gains no guesses at the owner's code (attempts are capped per request, and the stranger's
wrong codes no longer use up the owner's). **The price, in plain words, until the way out below
reaches the person (the server keeps it; no app and no option of `andvari-cli` sends a value yet):** anyone who knows a person's address can keep that person from asking the operator for
help, with five requests a window, for as long as they keep it up. The person gets those five mails
each window and so knows that someone is doing it, and the recovery kit is not affected. The cap protects the
mailbox of a person someone else names, which is why it stays. Not done: counting per caller network
beside the address, because a caller with many networks spends a ceiling per address as easily as one
spends the cap today, so it would add a rule and no protection; and a per-requester cap, which would
need a requester identity the route does not have. **The way out through the mailbox** (decided on
2026-11-17: built on the new line before the public launch; spec 03 §18.1): the code mail of every
request carries a mailbox value (sixteen symbols, 80 bits), and a request that names an unused,
unexpired value of that address is taken as a real one past the cap, with a ceiling of its own of five
per window and a mail budget of its own of five per window. A value does nothing for an account in the
private posture. **What it closes:** a stranger who knows the address can no longer keep its holder from asking
the operator for help, because the holder reads the value in one of the stranger's own mails and uses
it; a wrong value changes nothing and the answer is the same whatever value is sent, so the value
tells a caller nothing and cannot be guessed in useful time. **What it does not close:** a person who
cannot read their mailbox cannot use the operator's help at all, as before (the request's code goes
there); and a person whose address is being used this way still receives up to five unwanted mails
per window, which is what the cap is for. **The bound, in windows:** each cap counts in a window of
24 hours that starts at its first request, and the address's window and the value's run
independently; so within one window of each at most five plus five request mails reach an address,
and across the windows' edges up to twenty inside 24 hours, more than ten only through requests that
name values, which only a reader of the mailbox can send; a stranger who cannot read it still causes
at most five per window. **Whoever reads the person's mailbox** gains at most five more requests per
window, each still behind the mailed code, the seven-day hold, the account's bells and the veto, and
can spend both the address's five and the value's five themselves, so closing the way out for the
person: that is part of what reading a mailbox means. A queued code mail holds its code and its value
in clear until it is sent or the code expires (spec 03 §14.5). **A cost:** the value's alphabet keeps
symbols that can be confused when typed from a mail (S and 5, Z and 2, B and 8, G and 6), because a
value is mostly copied, the mail shows it on a line of its own in four groups, and a smaller alphabet
would need a seventeenth symbol. **Kept, and not yet (2026-11-17):** the server and the shared code
keep the way out, and `andvari-cli` takes the value since 2026-11-17; no app shows the value's field
yet, and spec 03 §18.1 lists what the shared code does not keep yet.
**R38 A register link that is not bound to an address tells its holder that an address is taken.**
Whoever holds an unbound register or enrol link can try addresses at `POST /auth/register` (spec 03
§14.3): one that has an account is refused `409 email_taken`, and the refusal does not use up the
link. Accepted as it is (rule of 2026-11-16): the holder of such a link was invited, the route is
limited per caller address, and a registration cannot go on without being told. A ticket proves the
address and a bound link checks it, so neither is affected. Since 2026-11-17 the address is looked
up before the password hashing, so a refused try costs the server nothing.
**R39 A neighbour on the same network can spend the limits per caller address.** The routes that need
no session are limited per caller address (spec 03 §0.2's index), and an address here is one IPv4
address or one IPv6 /64: a household, an office, a VPN or Tor exit, or a mobile carrier's shared
address can hold many people. Anyone behind the same address can spend those limits for all of them.
The two that matter most: **the sign-in's** (`login`, 5 a minute by default, which the device-link
pickup shares), which about 7,200 requests a day keep spent, so that nobody behind that address can sign
in or pick up a device link; and **the refresh's** (30 a minute), which, drawn per address for every
token, kept everyone behind that address from refreshing a session (on a mobile carrier's shared
address that could even happen by accident). Since 2026-11-17 a token that names a live session draws
its device's own bucket instead (spec 03 §0.1), so spending the address's refresh budget keeps nobody
with a live session from refreshing. The others only make an action from that address wait a
minute or an hour: the first exchange of a sign-in, registration and the sign-up codes, the kit's
verify and both commits, opening a recovery request and entering its code, its poll, a device link's
claim and poll, a link's fetch, and the instance, policy and recovery-key reads. Accepted: the other
road is always another network (mobile data, home), sessions already open are not touched, the kit's
verify keeps no counter per typed address (spec 03 §8), and limits per address are what bound a caller who has no
session at all.
**R40 "Removed by you, from <device name>" names the device as it named itself.** When a device of
the account removes another, the bell and the `device_removed` mail say that the account removed it
and from which device, and the server's record names the removing device by its id (spec 03 §16.7).
The name shown is the one that device chose for itself at its sign-in, unchecked: anyone who has the
password can sign in as a device named like one of the person's own. So the line can be trusted, as
far as the server is honest, for this much: a device signed in to this account with the password
removed the other one. It cannot be trusted for which of the person's devices that was; the devices
list (spec 03 §16.7) shows every device of the account, each with its platform, its time of creation
and how it was added, and an unfamiliar one is removed there.

**R41 A replaced refresh token inside its minute.** A refresh whose answer was lost would otherwise
sign the person out with a reuse on record that is no theft, so the server answers a replaced refresh
token presented again within sixty seconds of its replacement with the same pair that refresh
answered, while that pair is untouched (spec 03 §2). That is the released line's trade, kept as it is:
inside that minute, whoever holds the replaced token gets the device's own live pair and can use it
beside the device, until one of the two uses or refreshes it, and a holder who never refreshes keeps
the access token's lifetime (up to an hour). What bounds it: each such answer draws the caller
address's allowance for refreshes (30 a minute), so the grace is no free door; each is recorded as
`refresh_grace` (the account, the device and the caller's address), which is what shows it to the
operator and the person; the server keeps the pair in memory for the minute only and drops it when
the minute ends; and after the minute, once the pair was used or refreshed, or after a restart of the
server, a repeated refresh is a reuse and every session of the device ends, with its record. Only
whoever could read the device's tokens holds a replaced one. **The device's own second try**
(rules of 2026-11-18, spec 03 §2): a device sends a refresh that got no answer once more, within
fifty seconds of the first try's sending, so that it arrives inside the server's minute, and never
after: a token sent again later would be taken for a reuse, end every session of the device and
record a theft that did not happen, which would teach the person and the operator to disregard
the one record that shows a real theft. So the record that a refresh is out is written before the
request goes and is cleared only by an answer in the server's own envelope, and where no try is
left the device ends the session itself, sends nothing, and keeps the token only for the next
sign-in to name. The window is judged by the wall clock, so that a restart earns no try; **a clock
set back** inside the window by less than the time that passed can let a late second try go,
which the server then takes for a reuse: the person signs in again and a reuse is on record
(accepted, 2026-11-18). The shared code and `andvari-cli` keep this since 2026-11-19 (a second try
answered "slow down" or with a server error leaves the record, so no third try is sent). **"Never
left" at a renewal** (2026-11-19): it is the transport's word (R11: only a failure of the connect
itself, with no earlier attempt attached), taken as it is. A wrong "never left" would cost this: the
device would present a token the server had already replaced once more, the server would read it
as a reused token and end every session of the device, and the person would sign in again; nothing
is disclosed. To keep that from happening, a secure connection that fails while it is being set up,
a proxy's refusal and a network the platform reports as a plain socket failure count as "a request
went and no answer came" although nothing left, so such a failure costs one of the two tries;
a network the platform reports as a failed connect ("no route to host" everywhere; an unreachable
network on Android) is "never left". On an iPhone the transport never reports that a request did
not leave. Since 2026-11-19 the shared code puts the record back where the transport says that
nothing left the device, and keeps it after every other failure without an answer.
**In the browser and the extension** (the rules of 2026-11-19, spec 03 §2, kept in both since
2026-11-19; before that, a refresh whose answer was lost was sent again at the next request and the
server recorded a theft): the server answers any number of repeats of a replaced refresh token for sixty seconds from
the replacement (inclusive) while the new pair has authenticated nothing; the browser sends at most
two within fifty seconds of the first, the second by the tab itself twenty-five seconds after the
first where the tab is alive. Without locks between tabs, or while storage is not yet the same in two
tab processes, a third send can go, all inside the fifty seconds, which is harmless inside the grace
unless the pair was used in between (accepted). A refresh whose answer never came and had no try left
ends the session in this browser, and nothing is sent again: if the token was in fact never received
by the server, or was taken by someone else, no theft is recorded, and the other holder's session
lives until the person's next sign-in in this browser names the kept token (it then ends, recorded
`sign_in_named_replaced`, not as a theft); so the line for that end says to sign in again on this
browser, and why. **The kept token:** a token kept from a renewal that got no answer stays in the
browser's storage until the person's own sign-out of that account there, that account's next sign-in
there, a forgetting, or four newer accounts' keeps (the fifth pushes out the oldest, unnamed); where
the person does not sign out and the server never received it, it is a live token for up to thirty
days, readable by whoever can read that profile's storage. **After the person's own sign-out** of an
account nothing of that account's unconfirmed session stays in the browser: in the shared storage at
once, and on a browser where each tab holds its own session once every tab has handled the sign-out.
The server's chain then lives until it expires (thirty days), until this browser signs in and then
signs out, or until this browser is removed from the account's devices; nobody holds a token of it,
and the sign-out says so with those two ways (a sign-in again alone does not end it on a browser's
row; in the extension it does). **With the offline copy on,** a tab that has not yet handled another
tab's sign-out still holds the old pair in memory; it sends a refresh token only if the shared record
holds that same pair at that moment, since that token sent later would be taken for a theft and end
every session of the browser. A tab whose record is gone, or holds another account, sends nothing
and ends (as signed out elsewhere, or saying that another account is signed in on this browser
now); its server session, where another tab had not ended it, lives unheld until it expires. So a
browser with the offline copy on holds one account's session at a time: a second account's tab on a
browser shared between accounts ends at its next renewal, and its chain lapses unheld (accepted). A
tab whose own sign-in could not write the record sends no refresh token at all and says that the
session could not be saved. A person's sign-out tells the other tabs to drop that account's kept
token, best effort: a tab not open, frozen, or in a browser without a channel between tabs keeps its
own until its next sign-in, a forgetting, or its closing. Between tab processes whose storage is not
yet the same, the record can vanish between the read and the mark (accepted, as above); an answer
with a new pair that lands after another tab's sign-out is taken up by a tab that had not handled
that sign-out, and that chain is then held by nobody until it lapses. **What reads as the
server's:** a proxy that replaces the server's
refusal of a renewal with a page of its own makes a real revocation, or a real theft's refusal, read
as "not confirmed", in the browser and in the extension; an answer of a gateway shaped like the
server's, with both the code and the message, reads as the server's. **The extension** holds a marked
token in its worker's memory only: a restart loses it and earns no try, and the next sign-in on the
extension's row ends that row's earlier sessions anyway; a worker restarted while a renewal was out
ends the session as not confirmed at the first need of a renewal, sending nothing and keeping no
token. The refresh route is not version-checked, so a stale client's renewal never answers
"upgrade required". An honest person can be signed out by this
rule where an answer was lost (accepted). A clock set back by less than the time that passed lets a
late second try go and meet the reuse rule (as for the tool).

**R42 A signed change that reached the server, while its place is free.** A change of a vault's log
is signed by the device, and once its frame has reached the server, the server can append it at its
position at any later time for as long as nothing else took that position: a change the device gave
up, withdrew or called "not made" from a read where no answer had named a head is therefore not
gone for certain (spec 03 §10.3). What bounds it: the device remembers such a change by its hash and
its position for as long as that position is free, and if the log later holds it, the person is told,
with the way to undo it; the person's own next change of that vault takes the place and ends it; and
"not made" is said after a sent change only where a read reached the head the server's own answer
named. A server that appends it late gains nothing the person had not signed. **The cost of the bound
on what is remembered** (accepted, 2026-11-19): the web client remembers at most eight such changes
for one vault, letting go first of those already told "not made"; a person who withdraws more than
eight changes to one vault while nothing reaches it is not told if the server makes the oldest of
them after all. The shared code is to bound its records at sixteen and thirty-two, in the order spec
03 §10.3 gives, with a cost of the same kind (rule of 2026-11-19, not built yet). **A tab that still runs the code from before a deploy** rewrites the records at rest in
the old form until it reloads (from then on a reader carries what it does not know and never
consumes a record of a newer form, but an old tab predates that rule): what it drops of a newer
record is not remembered (accepted, 2026-11-19). The web client keeps this since 2026-11-19 (it
remembers what it gave up, withdrew or called not made, bounded at eight, and says a later append).
**Not kept yet (2026-11-19):** the shared code does not yet remember such a change.

**R43 A member's save between the read of a vault and its deletion.** Before a half-made vault of a
stopped move is deleted, the device reads it and deletes it only if it holds nothing but the move's
copies (design §3.13). A deletion names only the log's head, never the items, so a member's save that
lands between that read and the deletion (a second or less) goes with the vault, into its grace,
where the vault's owner can still restore it. The deletion is to carry the point up to which its
items were read, and the server to refuse it when any item is newer (spec 03 §11.1); the server keeps
that refusal since 2026-11-18. **Counted by its id** (accepted, 2026-11-19): a copy the move put into
the trash counts as the move's by its id, so a member who restored it, changed it and deleted it
again loses that version with the vault; rows set aside because their first home was another vault
are not counted as a member's items. **The entry by which a move's new vault says what it is**
(`moveOf`, design §3.13; known limits, 2026-11-19): (a) any member who may rename a vault can write
the entry into its description; the only effect is that a vault with nothing at all in it is deleted
at its owner's next move out of the named vault (said in that move's result, restorable while its
grace lasts), and a vault with anything in it is kept and named. (b) A device that holds a record of
its own stopped run does not look for another device's stopped run by the entry, so that second
target stays unsaid on that device. (c) As for every half-made vault, the decision rests on a read
from the server: the server's refusal of a deletion whose read is older than the vault's items
narrows the window against an honest server, and nothing narrows it against a server that hides
items (R20). **A member who keeps saving** (accepted, 2026-11-19): a refusal for items that moved
on gives back its draw on the deletion limit, but the account's own ceiling counts it, so a member
who keeps saving can make an owner's deletions fail for as long as they save, and after forty such
refusals in an hour the account's own limit answers; the way out is to remove that member first
(spec 03 §11.1). **Kept since 2026-11-19:** the web client reads a half-made vault before its
deletion and sends the point it read, and the move's deletion of the old vault names its point too;
the shared code reads a half-made vault before its deletion and deletes it only where it holds
nothing but the move's copies. **Not kept yet (2026-11-18):** the shared code sends no point, so for
the apps the window of a second or less stays (since 2026-11-19 the engine carries the point in the
request; the move that names it is built and held, 2026-11-19).

**R44 What a device's plain records name.** The records a device keeps outside what is sealed hold
public ids, numbers and sealed blobs, and besides those **the addresses and the servers of the
accounts it knows** (in the keys of its records, in the device's row, in the keeper's record of
which account an address is, and in a kit notice's mark): an address is not content, and a reader of
a locked device's files learns which addresses were used at which servers, and that a kit was
wiped for one (accepted, 2026-11-19). After a forgetting of an earlier account, one plain record
names the address at its server (the notice's mark: the address as typed, no id) until the notice is
dismissed, the server is forgotten or the account under that address is deleted on this device, also
where no account was taken after the forgetting (rule of 2026-11-19; kept in the shared code since
that day). They hold no vault name, no name of a contact and nothing of
an item: a move's note at rest holds ids, the names of its lines' keys and numbers, the member as
the account's id and public key, and the names are filled in when the note is read with the account
open (the shared code keeps this since 2026-11-19); the records of changes to shared vaults name who
was added to, removed from or offered which vault, and when, by id, for every change held, withdrawn,
given up or found. **Someone who can write the device's plain records** can change what they say;
a move's note read from them shows only the move's own lines, each in its own shape, and a member
only as the device itself knows that person, so such a writer cannot make the place of the notes
show any other sentence of the app (kept since 2026-11-19). **What a server can make a line say:**
a server can make the operator's console say that a sound policy was refused for a reason it names;
the console is to say that the SERVER refused it for that reason, never state it as a fact about the
policy, and a server's "wait this long" is to be clamped (a day at most; beyond that the line says
"later"), so that no line with a wait shows an absurd number (rules of 2026-11-19). Kept in the shared
code since 2026-11-19: a refused policy carries the server's own message for the refusal, handed to
be shown as the server's words, and a server's wait is taken only as whole seconds from none to a
day, any other value or none being said as "later", without a number.

**R45 A frozen vault.** Where a server's own answer named a change at or beyond its position and
the server later serves another entry there, the server's answer and its log cannot both be true:
the vault is frozen on this device for good (in a browser, while its storage has room and no server
that lies times its answers to two of its open tabs: the paragraph after R47), its held change is
dropped and never sent, nothing is said of the change, and the vault is read-only here. The freeze comes at the device's next complete
verified read of that log, with nothing else called (kept in the shared code and in the web client
since 2026-11-19; before it, both froze only when something next touched the held change, so a
server that contradicted its own answer could have items go on being written into a vault whose
history it forked for as long as nothing touched that change). A read from which the server withholds entries can verify the other entry's
hash without the check; the vault is read-only while withheld, and the freeze comes at the next
complete read. Only removing the device's records of a frozen vault ends the freeze (forgetting
the server, the account, or the earlier account), except in a browser, where a server that lies and
times its answers to two open tabs can also make it forget the freeze (the paragraph after R47); no
lying server is needed to undo it, and nobody but the server can bring it about. No honest sequence of answers and requests is known to freeze a
vault (accepted, 2026-11-19), with one exception that is not a lie: **a server whose database is
restored from a backup has lost entries it had acknowledged;** where another member then writes at
such a position, every device that holds the acknowledged entry (as a change the server called
stored, or in its verified log) freezes that shared vault, and it stays read-only there until that
device's records of it are forgotten (in a browser, while its storage has room for what the rule
keeps: the paragraph after R47). A device cannot tell a restore from a lie; this is the rule
working as designed, and it is what an operator must know before restoring a backup (R47). A server can also keep a held change "stored by the server's word" for
as long as it wishes by answering its sends as stored without storing it; meanwhile the vault takes
no new log change from this device, which is the denial of service a server can always cause by not
storing, and the person is told that the server says it is made. A change refused for good while
the server's own earlier answer called it stored is said as refused, never as not made; a change
recorded as "cannot tell" before a send that then never left stays "cannot tell" (the cost is
wording, never an untrue line). A change the server answered as stored waits, and blocks the vault's
next log change from this device, until the log shows it or the server contradicts itself; if the
server then never serves it, it waits for good, as it would if the server never answered at all
(accepted). A server that refuses every send because the session has ended cannot keep a change
unsaid past the day: the general re-send gives it up after a read. Keeping the highest head an
answer named freezes a vault only where the server contradicts its own answer; the one road found
beyond that is a server's replay of another vault's answer with a head at or beyond the change,
followed by an honest loss of that position, which is the same class as any fork a hostile server
can cause (2026-11-19). **The web client** (spec 03 §10.3): the server's word is any success answer
at or beyond the change's position, whatever hash it names there (rule of 2026-11-19; an honest
server answers success only for a frame it then holds at its position). Kept in the web client
since 2026-11-19: the word survives a refused re-send, an acknowledgement that arrives while the
person withdraws, and one of a half-made vault's deletion that is then dropped, so a server that
answers success while storing nothing cannot avoid the freeze by those roads; at the freeze the
held change is dropped and nothing of it is sent, shown, asked, given up or counted. Before it, the
browser froze only at a later touch of the held change and never after an answer beyond the
change, and where it froze it kept the change and sent it again at every unlock. **A member may
leave a frozen vault** (rule of 2026-11-19): the leave names the history that member's own device
verified, so it fits no other history and is no road around the freeze; it is the only entry the web
client posts to a frozen vault. A removal of a frozen vault learned at a sync is never quiet, also
after the person's own leave (rule of 2026-11-21; spec 03 §10.3): the browser keeps a copy of what it
held of the vault when it learned the removal, for 30 days, with the notice; the same rule, that no
departure from a frozen vault is quiet, is decided for the phone and the desktop before the first public
release (2026-11-21), and is not built. **What that keeps, said plainly (2026-11-21):** after a person's
own leave of a frozen vault, the browser keeps that vault's content, with this account's own wrap of the
vault's key so that it can be opened and items copied out, for 30 days, and where the server went on serving the vault
after the leave, that includes items written after the person left; this adds nothing to what a
person who was a member can read with a server's help (R7). Kept in the web client for a delta sync
and for a full resync alike: before a resync replaces what the browser holds, the browser takes what it
held of each shared vault, and a vault the fresh list no longer grants goes the same way from that, with
the same notice and held copy (spec 03 §4). Where the browser held nothing of the vault (the first full
list after a sign-in, or a reload with no offline copy), nothing is kept; it says in one line, without
the vault's name, that a vault frozen here is gone. **What the web client
hands out after a removal was carried out (2026-11-23):** once a removal from a shared vault has been carried
out in a browser (by its own sync, or by another tab of the same browser profile), these places hand out
nothing of that vault, each held by a test, and no others are promised: (1) a download of an item's file
whose answer comes after the removal opens and writes no file, whoever asked for it; (2) a backup reads
what it may hold again after its seal and its check, seals again from the new read where that read lost a
vault or an item (three seals at most; where the last read still differs, or nothing is left after such a
loss, no file is written and the panel says so), writes no file where the browser locked during the seal, and its card
names left-out files only of items still shown; (3) the vault list past 500 rows draws no row of the vault
when it renders by its own state; (4) an item closed by the removal after Save was pressed is never said
to be not saved where the server answered the save, and is said to be of unknown outcome while the
answer is awaited; (5) the account's deletion, which carries a signed leave of each shared vault's log, is
counted among the senders that change a vault, as a leave; (6) the sender of the one attempt before a
policy's wipe sends, of each batch any caller hands it, only the changes the question allows; (7) the
person's own items stay on show where the server serves no row for the own vault, a shared vault the
server serves no row for shows nothing, and no served label makes a shared vault the own one; (8) a copy
out of the vault (one item, or each item of a copy of all) puts no item into the target when the removal
is carried out while one of the item's files uploads, or after its files were uploaded and before this
browser sends the item to the target; (9) the breach check of an open item's password sends no prefix when the removal is carried
out during its digest; (10) a finished import's report into the vault is closed. The table of these places
was made by reading the web client's code once (2026-11-22); a place that reading did not find is not
covered. What stays as it is: the record of when an item was last used goes on holding the ids of the
vault's items and the times they were used, with no content. A copy refused at (8) leaves in the target
the files it had already uploaded, named by no item and sealed under keys that never left this browser;
the server removes such files at its hourly sweep (where it runs its background work) once they are more
than 24 hours old. After an answer beyond the change the web client says "cannot tell"
where the shared code says the server has the change (ruled on 2026-11-19; both freeze on a
contradiction, and the difference opens nothing). The shared code's engine keeps these rules since 2026-11-19, among them the freeze at the
read, an answer below
the change's position that marks nothing, and the highest head named that no later answer takes
away (spec 03 §10.3); the device's plain store names who was added to, removed from or offered which
vault, and when, for every change held, withdrawn, given up or found, and holds no vault name and no
content (R44). **What the rules for a change that waits take from a person, or leave open** (limits
found on 2026-11-21; spec 03 §10.3): (a) one false "stored" from a server blocks every later change
of that person to that vault from that device for good, with no withdrawal and no giving up; a way
out by the person's own word after the day, which says the truth (the server said it stored the
change and has not shown it; this device stops sending it; it may still be made), is to be designed,
on its own, before the first public release (decided on 2026-11-21), and is not built. (b) A departure's
quiet mark (the one that keeps the person's own leave or deletion from raising a notice) outlives its
act within one opening of the account, in every act; it is to be bound to the entry it was made for,
in every act, before the first public release. (c) "Not made and will not be" rests on the server's
"slow down" answers: a server that answers so and stores the change all the same is caught only by
the vault's member list. (d) As the two apps' "made after all" notice is drawn up, it offers "undo it"
also for a kind of change that has no undo; it is to get a form without it. Neither (c) nor (d) has a
date set.

**R46 What `andvari-cli` does not guard yet.** Since 2026-11-19 the tool keeps a record of each
account's identity key, looked up at its own server, the first time it takes or reopens that account
(trust on first use), compares every flow with it, both recoveries' commits included (the session a
commit's answer opens is held to the record, so a party that holds the account key, such as the
operator who delivered it, can no longer have a commit's run taken under another key), and refuses
the same account under another key with no offer. Before that date the same account served under
another key was taken without a word on every road. The rules (2026-11-19, spec 01 §7): the tool
keeps a record of each account's identity key per server, checked on every flow, a recovery's commit
included, and refuses the same account under another key with no offer; it keeps a record of which account an address is at a server that
outlives a sign-out and the server's end of a session, as the apps' record does, and goes with the
forgetting (the key's record stays), with `forget-server` and with the tool's own confirmed deletion
of the account; a lock on its home is taken by every command that changes a session or a tie, so
that a second shell cannot write back a tie another shell forgot. The record of the address is kept
since 2026-11-19: written at the first session the tool takes at a server, compared on every road,
another account under the address refused with both possibilities and the offer. The lock on the home is kept since 2026-11-19: every command holds it
from before it reads the home until it ends, a second command waits a bounded time and then stops
having sent and changed nothing, and a lock left by a killed process blocks nobody; so a shell that
still holds the earlier account's session no longer writes the tie back after another shell forgot
it, and a commit whose check passed no longer saves its session over a tie that another shell made
meanwhile (both closed that day). The forgetting removes the tie (the saved
session) and the account's local records, and keeps the key's record. **What it did not guard
before the record of the address (until 2026-11-19):** the tool's only tie between an address and an
account was its saved session, which goes at a sign-out and whenever the server ends the session,
so a sign-in, and every other road after the first command that followed such an end, could take
ANOTHER account under a known address without a word. A home from before the record has no such
record until its first session at each server, and takes the account served then as the
address's (trust on first use). After the tool's
confirmed deletion nothing stays, the key neither, as for every client (R19(c)): a deletion is
confirmed by the server's answer alone, so a server that confirmed a deletion it did not make makes
the tool forget the account's key and the address's record and can later serve that account under
another key to this home. The rule (2026-11-19, spec 01 §7) is that a confirmed deletion removes
only records of its own server, and that a request for the operator's help kept for another
address there counts as something of another account kept, which keeps the server; kept since
2026-11-19, for the deletion and for the forgetting (before that, a deletion removed at every server
each record that named the deleted account's address, account id or device id). A deletion
confirmed by a server that lied makes the tool forget the account's key and the address's record
and, where nothing of another account is kept there, the server itself with its pin. **What it
cannot keep apart:** the shared code keeps some records of an account by its id alone (the stored
account state with its checkpoint and high-water marks, the vault logs' live mark, the recovery
mirror); two servers that name the same account id share them on this home. `forget-server` goes
through the shared code and keeps them where another server ties the account (since 2026-11-21, T1);
**not kept yet (2026-11-21):** the tool's own confirmed deletion and its forgetting of an earlier
account remove them without reading that tie, so the other server's next read is a first sight, and
it can serve an older state once without being caught. Ids are random and made by the registering client, so only
a server that names an id it learned elsewhere reaches this. The lock on the home orders the tool's own
commands only (it is advisory: another program can still change the home). A home from before
the record trusts the first key it sees at its next run (accepted: nothing of the tool was released).

**R47 A server restored from a backup** (design §9.6; the operator's steps in `docs/self-hosting.md`,
"Before you restore a backup"). A restore is the operator's own act, and it undoes what the server did
after the snapshot. **What it brings
back:** the database as the snapshot held it. Saves made after the snapshot are gone from the server
and left only on the devices that hold them; a master password changed after it is undone and the
former one signs in; devices revoked after it are known again, and their revocation is no longer in
the audit log; accounts disabled or deleted after it are back, a member removed from a shared vault
after it is a member again and can read it, and a recovery kit or two-step setup replaced after it is
undone (a kit or a second factor replaced because of a leak is in force again); mail waiting at the
snapshot is sent again; invites, links, device links and requests for the operator's help ended after
it are in progress again. A device that synced after the snapshot refuses the older state, applies
nothing and keeps what it holds (shown by tests since 2026-11-20); a shared vault whose members changed
after it can freeze for good on such a device (R45; how far that holds in a browser is said in the paragraph
after this entry). **What `andvari admin restored` ends** (kept since
2026-11-21; run once on the put-back database before the server starts): every session of every
account, the operator's included, so no token a device holds is accepted any more; every device not
revoked is marked signed out; the invites, links and device links in progress; and every request for
the operator's help in progress, an answered one included, so nobody can finish a request the
snapshot brought back as ready. It removes no data, changes no password, key or setting, leaves the
change counter, tells devices nothing and writes nothing a device must believe; its one record is in
the server's own settings, served by no route. It refuses before it opens anything beside a leftover
write-ahead file, its companion or a rollback journal, and while any process on the host has the
database open; through a symbolic link it looks beside the link, while SQLite uses the files beside
the file the link leads to, so a leftover write-ahead file there gets past it and damages the put-back
file as below (not kept yet, 2026-11-21). **The server's other commands and its start have
no guard yet** (decided on 2026-11-21, not merged): a write-ahead file beside a database whose header
does not say write-ahead mode is to be refused before anything opens it, through a link too, and
`andvari setup` beside leftover files is to create nothing; until then a write-ahead file of the
replaced database beside the put-back file is applied to it at the first opening by the server's start
or any of those commands: the put-back file is damaged for good (the command then ends with an error),
and the leftover files are deleted, so only the backup's file brings it back; a rollback journal of
another database is rolled into the put-back file without a word. **Limits that stay with the guard:**
a link whose target does not exist yet (no database is harmed; a leftover write-ahead file there is
deleted by SQLite; to be mended before the first public release); a hard link (its leftovers lie beside
the other name); a link swapped between the guard's look and the opening; a put-back file that is itself in write-ahead mode, which
only `andvari admin restored` refuses; and a journal of another database, which nothing can tell from
the database's own, since a rollback journal carries nothing that ties it to one database file.
**What it cannot end, accepted on 2026-11-20:** a device revoked after the snapshot
holds a device secret the server knows again, so with the account's master password it signs in as a
known device, with no link where the account requires one for new devices and no new-device mail; the
server keeps what makes a device known so as to lock nobody out, and neither the server nor the
operator can tell which devices those were. The operator revokes them again at once, before members
are told to sign in; until then whoever holds such a device and the master password is back in. After
the command a requester's device says that its request is over and offers to ask again. Since
2026-11-21 the shared code's three lines for that end (ended from the account's side; cancelled
because the master password or recovery setting changed or the account was recovered; ran out of
time or was used, the last a result of its own after the operator's help) each add "or it was ended
by whoever runs the server", naming no restore, and await the owner's words (design §9.6). **Not kept
yet (2026-11-21):** neither app draws the first of them yet: the phone shows its own narrower line
there, and the desktop a general line for the request's stage. **The two harms the counter leaves, with their rule
decided and not built (2026-11-21):** the server numbers every change with one counter, which the
restore takes back, so (a) **the silent skip:** a device that synced after the snapshot, once new
changes carry the counter past the number it had reached, syncs normally again and never receives the
changes made under the numbers it had already seen, and nothing says so; and (b) **what only a device
holds:** items and newer versions saved between the snapshot and the failure exist only on devices,
and nothing says so. The rule (design §9.6): the command raises the counter past every number it can
have handed out, and each device that sees such a jump compares what it holds with the server's full
list, keeps and marks what the server lost, and offers to send it back, copy it into another vault or
remove it, doing nothing without its person; the two parts merge together, never the jump alone
(the jump alone would make (b) worse: the older state's warning goes, and a full pull the server
demands replaces the device's rows). Devices are never sent a signal to accept an older state
(decided on 2026-11-19), and a server that lies gains nothing from the step: it can make a device
mark items and ask for their history, and it loses the power it has today to make a device drop items
without a word by demanding a full pull. Until then (a) and (b) stand as the guide says them, and a
device that keeps no copy (a policy that forbids one, a browser without the offline copy, the
extension) loses after the forced sign-in whatever it showed that the server no longer has.

**How far the browser's rule for a shared vault after a restore holds.** The web client keeps what the rule
rests on (the history of each shared vault it verified, and whether that vault is withheld or frozen)
in the browser's storage, which every open tab of one browser profile shares. Against an honest
server, a restored one included, the rule holds while that storage has room for what the rule keeps;
this is known by reading the code and from a model of the browser's storage in the tests, not from a
run in a real browser whose storage is full. Against a server that lies, it holds only while that
server sends the genuine web app (T6) and does not time its answers to two open tabs of one browser:
a tab that runs in a process of its own writes from its own copy of the storage, which can lag
another tab's write, so a server that times its answers so that the two tabs' writes cross can make
the browser forget what it had verified, or forget that a vault is frozen, and a change is then sent
into that vault (a reading of how browsers keep storage for such tabs; the lost verification and the
change sent were shown in a model of that storage, the lost freeze by reading alone, and none in a
real browser). With two tabs open, honest use can also make a vault read-only
for a while: a tab's read that was answered before a new entry and is stored after another tab
stored that entry leaves the vault withheld in both tabs, and a save there is refused, with nothing
sent, until a later read.

**R48 What stays on a device of an account that ended** (spec 01 §7, design §3.11). Since 2026-11-21
the shared code's app engine (the phone and the desktop app; not `andvari-cli`, whose deletion and
forgetting do not read the tie either, R46, and which has no such removal: not kept yet, 2026-11-21)
removes every record it keeps by the id of an account the device no longer knows anywhere, whatever
the tie between servers said: at every start, and at the end of a confirmed deletion, of both forms of
"Forget this server" and of a completed forgetting of an earlier account. It does not run at a
sign-out, nor at "forget the account on this device" after a deletion whose outcome is not known (a
signed-out account stays known by its address record). No way was found on 2026-11-21 for a server's answers, or for a stop with a whole start
between any two writes of a registration, a sign-in, a recovery with the kit, a device link, a
password change, a sync, a forgetting or another account's deletion, to make it remove a record of an
account the device still keeps or is taking. **Its limits, as merged (2026-11-21):** (a) **it removes
nothing while it cannot read what it decides by:** where the store cannot list its keys, or where the
session record, the list of held copies, an address record at any server, the record of the person's
own ends, the forgetting marks or a mark of a deletion of unknown outcome cannot be read or does not
parse as its form. No server answer and no build writes such a record, so this needs a damaged store;
on such a device the records of ended accounts stay for good, as they did before the sweep, since no
reader of the engine clears such a record yet. The engine then writes one line to its diagnostic log,
and no app passes that log on yet, so nothing says so. (b) **A
take writes the address's record first,** then the identity record: a stop between the two leaves the
address tied to that account at that server, under the same key; a later sign-in of that account there
is taken and writes the identity record, and another account served later under that address there is
refused as a fault, with the forgetting of the earlier account offered (the strict side). (c) **A
registration the session keeper refused** leaves the device's records of the person's recovery choice
(the recovery mirror and the escrow mark) with nothing that names the account; they go at the next
start, and the person is asked the choice again (the safe side: the sealed record of the choice was
never written). (d) **One engine per device state:** no shipping app runs two engines over one store
(the phone builds one engine per process and runs no second process; the desktop app holds a lock that
refuses a second start; the iPhone app is not yet on the engine, and the engine's seam built for it
keeps the device state in the app's own container and gives its extensions only the fill snapshot and
the save queue in the shared app group), and the store's writes are safe within one process only: two
processes over one store would lose each other's writes, whatever the sweep does. (e) **An account that lives at a server's new address** while its address
record lies under the old one, forgotten at the old address, keeps everything only where a session or a
held copy is kept for it at the new address; where neither is, its records go, and its next sign-in
there is a first sight of that account at a server whose own identity stays pinned. (f) **A deletion
stopped part-way** is finished at the next start (since 2026-11-21): the deletion writes a mark of a
deletion begun before its first removal, and the start finishes what it names by the deletion's own
steps, the server's pin and records included, so the server is a first sight when it is met again. A
take at that server of the deleted account, or of any account under the address it was known by
there, removes the mark before the take writes anything of its own, and nothing is removed for a mark
that ended, so the finish never takes what such a take uses, also after a sign-out or a lost session
record; a take there of another account under another address leaves the mark and keeps that
account's records and the server's pin. A stop exactly at the mark's own write leaves the device as
before the deletion, while the server has deleted the account: the device keeps a session its server
no longer knows, and the server refuses its next use. A record of deletions begun with an entry that
does not read is written again at the start from the entries that read (one that does not read at all,
as empty), with a diagnostic line, and nothing is removed for a dropped entry; until that start such a
record holds the sweep back. **Not kept yet (2026-11-21; decided that day, before the first
public release):** while the secure
store cannot read its session record at a start (the phone, and the iPhone's seam, then hand the shared
code no session), the
offer to forget an earlier account is not to be made and the forgetting is to refuse, as where that
record names the account; until then a server that serves another account under the address in that
state can lead the person, by their own two confirmations, into removing the kept account's address
record, identity record and copy. A damaged line of the held list, damaged forgetting marks and a mark
of a deletion of unknown outcome that names no account are to be dropped by the engine's own readers,
so that their next rewrite clears them and one such record does not hold every later sweep back for
good; an address record or a session record that cannot be read still holds it back, since either
could name an account the device must keep. Where something ends, the tie is also to count an account
that the sweep's rule calls known, read before anything is removed (today, in a state that no known
sequence of events reaches, a deletion at one server removes the records of an account whose copy is
still held at another). Decided on 2026-11-21 as well, with no date set: each app is to pass the
engine's diagnostic log on to its own.

**A13 (security review 2026-10, third API review: release scripts and the remaining LOWs).** (a) **The signing
workstation pins the release commit and checks it against its own record** (c03; A13 review RF1, RF7): `signandvari
<ver> -Commit <sha>` refuses a tag that does not resolve to the pin before anything is checked out, fetches only the
release tag and never forces it (a moved release tag stops the run, naming both commits; another tag that moved on the
remote is not fetched and cannot block a ceremony), re-checks HEAD after the checkout and before the ceremony, and
`prestige-release.ps1` records the pin in `bundle.json`. The pin is NOT out of band: it comes from the build host's
handover line, which reads the build host's own tag, so it closes a tag moved by anyone other than the build host, a
tag moved after the handover line was printed, and an accidental re-tag, while a compromised build host chooses both
the tag and the pin. The layer aimed at that is held by the workstation: the commit its last successful ceremony
signed, recorded outside the repo and moved only after `prestige-release.ps1` succeeded and `bundle.json` records the
pin. Before any of the tree's code runs, the release commit must descend from it; a stat, the commits and then the
full diff since it are printed, every line taken from git escaped (C0, DEL, C1, the line separators and the bidi
controls; A14 review R2-2; the invisible and space-like characters, a byte that is not UTF-8 as `\xNN`, and lines cut
at 400 characters on screen, whole in a review copy; A14 review 5) and read as bytes split at LF alone, so a CR cannot fake a commit line or a diff header (A14
review 3); the tree is checked out and must then be clean and byte-identical to the commit where the review covers it;
and the operator types the version; a run with no human at a console fails closed before anything is checked out.
**The review is default-include** (A14 review 3, C1): every changed path except a short explicit list of trees that
never run on the signing box (`app-android/`, `web/`, `extension/`, `server/`, `deploy/`, `docs/`, `spec/`,
`.github/`), whose changes are counted instead, and even inside those trees every build script, gradle property and
wrapper file, jar, PowerShell or batch file and git attribute file (`.gitattributes`, `.lfsconfig`, `.gitmodules`) is
shown. So ALL of `:core` and `tools/` are covered (the update-signer is handed the key's path and is a shadowJar of
`tools/update-signer` and all of `:core`, and Kotlin resolves an unqualified call to a same-package declaration from
any module on the classpath ahead of the default imports; A14 review R2-1), and so are the scripts, the whole gradle
build, any new top-level directory, and `app-desktop/`, whose MSI is the household's Windows client and runs on the
signing account once installed there. The earlier allowlist showed a newly linked module, source directory, classpath
file or agent jar only as the build-script line that added it, and never its contents (A14 review 3, C1); now only a
file linked from inside an excluded tree is out of the review, and the line that links it is shown and named as a
reason to stop. Not covered: the third-party artifacts gradle downloads (only the catalog that names them) and the JDK.
**The full diff** is printed by `signandvari` before checkout, paged by PowerShell and never by an external pager (Git
for Windows pages through `less -R`, which passes SGR), with `--text --no-textconv --no-ext-diff --no-color`, so neither
the box's diff settings nor any attribute file can hide, rewrite or recolour a change (C2). **The checkout** runs with
`core.hooksPath` pointed at an empty directory, no fsmonitor hook and the LFS smudge off, and afterwards every file the
review covers must hash with no filter to what the index holds (hashed by `signandvari` itself since A14 review 5, H1:
`git hash-object --stdin-paths` read its paths from a pipeline, which a UTF-8 `$OutputEncoding` on Windows PowerShell
5.1 starts with a byte-order mark), allowing only the CRLF git's own Windows checkout writes, and only for a blob git
would convert (no NUL, no CR; S4); a symlink or submodule there is refused. That closes a system LFS filter writing
unreviewed LFS content for a pointer while `git status` stays clean, and any other filter's output (C3). Every git
command blanks the LFS clean, smudge and process filters, and from the checkout on reads no attributes from the release
tree where git has `--attr-source` (2.42+). A reviewed PowerShell file with a byte above 0x7F and no byte-order mark
(5.1 reads it in the ANSI code page, where 0x91-0x94 are quotes) and a reviewed text file with a CR that no LF follows
(a line break to Kotlin, Java and PowerShell, not to the review) are refused (A14 review 5, S1, S2). Every way out
between the checkout and the confirmation (a refusal, a failed git command, Ctrl+C) puts HEAD back, in a `finally`
(C5); closing the window does not. `prestige-release.ps1` deletes and rebuilds the update-signer jar from the tree on
every real run, so the jar handed the key is that commit's, not one an earlier build left (A14 review 3). What the
build host sends back after signing (the drop's `sha256sum`, the read-back manifest's fields) prints escaped too (C6).
A release tree with two paths that are one file on a case-insensitive disk is refused before checkout (NTFS). A first
run compares against the commit in the workstation's own most recent signed bundle (`dist/` beside its signature,
highest seq; no seed at all while git tracks anything under `dist/` in any case, because git matches that path by case
and NTFS does not, A14 review 3, C4), or an operator-chosen `-Baseline`, which must be a strict ancestor of the release,
when there is none; a tag is never the seed, because a plain fetch or pull brings in new tags and a planted
intermediate one would hide every change up to it (A14 review R2-3, R2-4). The commit values the owner types come from
GitHub's own pages (the merge they approved, the tag's commit), compared in all 40 hex characters with the build host's
handoff (GitHub's tag and pull-request pages show 7; the commit page's address carries all 40): that catches a
mistyped, altered or never-published value, not a build host that pushed and tagged its own commit, against which only
the review stands. A dry run is not tree-free: once confirmed it runs the tree's `prestige-release.ps1` with `-DryRun`
on that account (which builds no signer). Residual accepted: this rests on the
operator reading the diff, and a compromised build host can still cut a descendant commit that changes the build; the
tree still runs its own scripts and gradle on the account that can open `update-signing.key`, and keeping the build
off that account is the longer-term fix and is not built. Separately, the Linux, Arch and extension digests the
ceremony signs come from `release-spec.json`, which the download origin serves unsigned, so a substituted spec and
artifact pair that agree with each other pass the workstation's checks (q15, open; the build-host watcher's
byte-compare of the spec is the remaining guard). Keeping the key off the build host therefore does not, on its own,
mean a build-host compromise cannot forge a signed update. (b) **Build-host scripts** (c02, c06, c07, q22, q50, q21):
root-owned Arch packages from any builder, a whole-image same-build proof, SHA256SUMS signed by the pinned release key
with every uploaded `.asc` verified against it, the Web Store token off argv, a live release's signatures kept by the
downloads prune, and a recovery drill that fails when it ran nothing. Release-script hygiene; none of it is a client
trust decision. (c) **The extension save/update banner's height** (q36) is NOT fixed in A13 and stays a residual: its
painted height still varies with the verdict (Save vs Update) and with the vault-derived name lengths, so a page that
drives a capture and hit-tests the banner learns whether andvari holds a login for this host and username, and whether
the vault is unlocked. It is not a small, contained change: since A11 (q14) the Update sentence names the destination
vault and warns that every holder can read it, up to about five lines, and a fixed box must either clip that warning
(refused) or reserve that height in every state, a visible design change that needs the owner's review. (d) **The
popup login-fill grant** (q39) is bound to the tab's top origin at mint, as the card grant is, redeemed only when the
browser-set `sender.origin` equals that origin, and voided whenever the tab reports a navigation starting (`status:
loading`), which every cross-document navigation does, same-origin ones included (A13 review I2 corrected this
sentence, which said a same-origin navigation kept it). The origin is bound at mint either way, so a document of
another origin can never redeem it. (e) **Android editor secrets** (q27: password, TOTP seed, card number and security
code; since the A13 review, RF5, also the notes and the attachment list, whose every reference carries its file key)
live in the ViewModel's editor session rather than in saved-instance state, so they survive rotation but not process
death; after process death the vault relocks anyway and the editor reopens from the stored item. (f) **Closed without
a new residual:** a kept row applied when its key arrives (native `reevaluateGrants`, the invitation path) now homes
the item as R17 states (c05); a contact unpin or re-pin wins the account-state merge under clock skew (q01/q23, spec
01, the contact-pin merge); the desktop update manifest and signature are size-capped while read (q19), and so, since
the A13 review (RF6), are the extension's (256 KiB / 1 KiB, a declared length over the cap refused before reading); a
malformed served `encryptedIdentitySeed` on the extension's quick-unlock redeem is the terminal `keys_damaged` refusal
with the enrolled blob kept (q38; it gates MALFORMED seeds only: a well-formed seed the server substituted still fails
to open and takes the `stale_uvk` wipe of the enrolled quick-unlock blob, which a 401 could already force, so the cost
is a re-enrolment, never a secret — A13 review I3); vault purge also blanks the v14 `signedGrant` (q43); backup-cli's
never-overwrite guard folds names as a case-insensitive filesystem does (q45); a seal refusal after web's offline-put
fold restores the folded rows (q54), and core folds them only once the new put is sealed (A13 review RF4); and the
Android Autofill-status screen, which clears FLAG_SECURE, no longer composes the attention area (q30). (g) **Not built
(A13 review I4):** `personal_wrap.wrappedVk` is not blanked when the vault it names is purged. The wrap is sealed to
the account's own UVK, so only that user can open it and they held that key already, and the items, versions and
attachments it protected are gone with the purge. Blanking it in place would make the served wrap unreadable or
absent, which every engine reads as the server damaging or withholding the personal wrap (a warning or a proposal for
the human), so it is not a small, contained server change; no reachable exposure is shown.

**R18 (server-supplied ids and the device-local trust records — security review 2026-10, plugin scan F1/F2;
branch A10).** Every id a server supplies (vaultId, userId, itemId, deviceId, the user ids riding a transfer)
is checked against the lowercase UUID grammar at the wire boundary on all three engines, in the API client
(the user ids riding a log entry are checked by the strict statement parse, spec 01 §5.1),
before it can reach account state, a cache row or a device-local record; a row with a malformed id is
dropped and surfaced as a `bad-id` anomaly, and a session or identity row with one is refused outright.
The device-local trust records themselves (pinned cards, per-vault verified log state, confirmed
pins, the recovery mirror, link records) are JSON records with a strict decode on core and web, and the
extension's records are re-checked on read. Pre-cut-over records are never read: the first launch of a
new-format build deletes them (spec 07 §3). Since A15 the extension's
records live in the extension origin's IndexedDB, not storage.local: a strict decode checks shape, and
storage.local, which content scripts can write, could not give the integrity the re-check assumed. Before this a
server-chosen vault id carrying a line break could, through one human Accept on a decoy, write forged
vouch and held-key lines for OTHER vaults (trust laundering through the record delimiter). Residual: the
grammar is a shape check, not authentication — a well-formed id the server made up is still just a row,
and the signed log and the adoption rules (spec 02 §10.4) decide whether its key is ever adopted.

**R17 (item home — security review 2026-10, root cause A §5; branch A1b; spec 02 §7.2).** Closes review A-4.
Residuals accepted: (a) **the home is device-local**, so the server chooses the FIRST home of an itemId on a
fresh device (or one whose cache was wiped: sign-out, a policy purge, a demoted web cache), exactly as it
already chooses which rows a fresh device sees; from then on no served row moves the item. **Narrowed in
branch A9 (LOW, every engine):** the first home is the vault of the first row this device APPLIED (live, blob
present, key held, envelope opened), never of a row it merely saw: a blob-less tombstone or a row under a
vault this device holds no key for, served first, records nothing (`skip`), so the server's choice is only
among rows the device can actually apply, and it can no longer home an item away from its genuine row (and
quarantine that row for good) with a row it needs no key to mint. A ciphertext row kept for a key that arrives
later homes the item when it is applied then, if the item still has no home. The same holds for
every SESSION of a client with no durable cache: cache-less web (`NullCache`, the default until the per-device
opt-in, spec 02 §8.1) and a native host on the in-memory cache (desktop before cache consent, org-forbid mode)
hold their homes in memory only, so each unlock starts fresh and the server picks the first home of every item
in each such session. Confidentiality holds there as well: a served row under the server's vault that wins the
first-home race leaves the genuine row QUARANTINED, never decrypted into the working set, so no plaintext of the
genuine vault is ever sealed under the server's key; what the user sees is the server's own plaintext, and the
wrong-vault notice is raised on that pull. A server that serves
a fresh device an item ONLY under a vault it keys reads nothing new (the plaintext it serves is its own). (b)
**the extension keeps its homes per server origin and user in browser storage** and rebuilds them from the
first snapshot after that storage is cleared. (c) **quarantined rows are kept as ciphertext** for diagnosis
only (native: the newest 256; web: one per item), never decrypted into a list, search, export, fill or capture
target. (d) **one notice per pull**, however many rows were refused, so a server that keeps re-serving the
same row raises the notice again on each pull (it is never silent). (e) a capture or editor that opened BEFORE
an item's home was recorded on this device (an upgrade mid-session) binds to the vault the item showed then,
which is the item's recorded home from that point on.

**R19 (account deletion — spec 03 §13, design 2026-11-10-account-deletion).** What a deletion guarantees: ONE
transaction removes the account, every session and device, every vault only it held (ciphertext, history, attachments
and — after the commit — their blob files, every key wrap on them), its memberships elsewhere (each with a `leave` the
account signed itself, appended to that vault's log), its escrow and recovery kit row, its usage ledger, account state,
personal wrap and genesis, its connections, links, device links and recovery requests; its audit trail is cut down to its security events under a fresh random pseudonym that
nothing on the server maps back, and those go 90 days after the deletion; the address can then register again only as a
NEW account. It is refused while the account owns a vault other accounts still use, or is the instance's operator (a
signed card handover comes first), so no member is left with an ownerless vault and no instance without an operator. The
operator may delete an account disabled for at least 30 days (W2, confirmed by the owner 2026-11-15, spec 03 §7.1): the same transaction
with **no leaves** (the person is not there to sign), so the account stays in its vaults' logs with no grant until an
owner signs "Remove from the list" (spec 02 §10.7); it is emailed to the captured address. Residuals accepted:
(a) **Not cryptographic erasure** (R7, extended to accounts): anyone who held a vault key while granted keeps what they
synced; the operator's backups keep every row until they rotate out (T7), and a backup taken before the deletion links the
pseudonymised rows back to the account by audit id; a hostile server can simply not delete (T1 — it never held more than
ciphertext and the §5 metadata).
(b) **Copies outside the database**: every audit line also went to the operator's log pipeline with the raw userId and
device id (never an email); those copies follow the operator's retention. The retained rows keep each event's IP for the
90 days — part of the security record the owner chose to keep; in the database, no row kept past those 90 days records the
IP of one of the account's requests or names one of its device ids (the deletion replaces each device id with a fresh one,
and any row a racing request writes afterwards carries neither). The leaves it signed stay in other vaults' logs under
its old userId and key, as the membership history the server already held (R25). Its address stays in the mail outbox
until the deletion email is sent, at most 24 hours (R31).
(c) **Other devices**: an offline device of the deleted account keeps its offline copy until it next reaches the server
(T3: the server then answers 401, which ends the session there; the copy stays until the person removes it, except on
the iPhone app, which deletes it). Every device other than the deleting one keeps its spec 01 §5
self-identity record and refuses a re-registered account at the same address on that origin until the record is removed
— the backstop cannot tell a new account from a swapped one, so this stays. The record is removed only by the person, on
that device (decided on 2026-11-17, spec 01 §7, design §4.4): the refusal says both possibilities (the account was
deleted and made again; or the server is not giving this device the account it knows) and offers "Forget the earlier
account on this device" behind a second confirmation, which says that if the account was not made again, forgetting means
trusting whatever account the server serves under that address from then on. What remains: a person who is deceived
into forgetting, while the server swapped the account, trusts the swapped account on that device; the server's pin and
every other account stay, and nothing a server or an operator sends can set the forgetting off. A flow under way
for the address blocks it, it removes nothing of an account the device still keeps or holds as its server's operator,
and afterwards nothing of the forgotten account is left on the device (rules of 2026-11-17, design §4.4); what a
server gains from a forgetting it talked a person into is in T1. The offer is for another account
only, and the forgetting keeps the record of the earlier account's identity key (rules of
2026-11-19, T1). The shared code has the forgetting with these guards since 2026-11-18, the app
interface hands it to the screens since 2026-11-19, both apps draw it since 2026-11-19, and the web
client has its own since 2026-11-19; the narrowed offer and the kept key record are not built in the
shared code yet (2026-11-19). **After a deletion that this device ran and its server confirmed,
nothing stays** (the owner's answer of 2026-11-18), the record of the key neither: a server that
confirmed a deletion it did not make can later serve that account under another key to the device
that deleted it. A deletion that a stop cut part-way is finished at the next start from a mark the
device writes only after the server's confirmation of a deletion the person asked for with their
password, before its first removal (since 2026-11-21). A take at that server of the deleted account,
or of any account under the address it was known by there, removes the mark before the take writes
anything of its own, so the finish never removes what that take uses (its address record, its
identity record, what is kept by its id, the server's pin), also after it was signed out; a take
there of another account under another address leaves the mark and keeps its own records and the
server's pin, and a take of the same account at another server keeps what that server holds and the
identity record. **Forgetting the account after a deletion whose outcome is not known**
(rules of 2026-11-19, spec 03 §13): the device asks its server once to end that session; where the
request fails, the session stays listed at the server until it expires, held by no device, and the
person ends it from another device; the account may still exist, so what the device knows of the
server and of the account's vaults stays, and so do its records of which account the address is
and of that account's identity key (a server can produce the unknown outcome by ending the session
during the request). The shared code keeps the request once and the vaults' records since
2026-11-19, and the web client keeps the address's and the key's records; the shared code's keeping
of those two records is not shown by a test yet (2026-11-19). Co-members keep whatever members list
their clients hold in memory, and their contact pins of the old identity key, sealed in their own account state where the
server cannot edit them: inert — the old userId can never be granted again (404), nor name a new account (its SHA-256 and
the pseudonym's are kept in `retired_ids`, and register refuses both as `user_id_taken`, so neither a pin of the old id nor
the 90-day audit purge can ever land on a new account), and a new account at the same address has a new key, so a
co-member's pin of the old key never matches it until the two connect again (R34). The digests are a residual of their own, accepted: anyone who
already holds one of those ids (an old backup, a co-member's device) can ask the server whether it was retired.
(d) **A stolen session** deletes the account only with the master password AND, where enrolled, the current TOTP code. The
password proof is checked before the code (rule of 2026-11-16, spec 03 §13), so a wrong or missing proof never tells
whether a guessed code was right, and the proof draws on its device's own back-off; with TOTP
off, a session plus the password can delete — as it can already change the password and lock the member out — bounded by
the hourly `account_delete` bucket (every reauth route a session holder can reach is more guesses per window, which is why
this one is per hour, not per minute).
(e) **Irreversible, no grace window**: a grace period would have to keep the credentials and both recovery paths alive,
the opposite of the deletion. The client requires the typed address, the password and the code, and offers a backup first.
(f) **An operator who wants to delete their operator account** hands the role over first with a signed card (spec 03
§17.2); an instance whose operator is lost recovers with `reset-instance-identity` (R30).
(g) **An account deleted and made again never comes back under its old id** on an honest server that
keeps its record of retired ids: the address may register again at once, the deleted account's id
and its audit pseudonym are refused for good under any address, and its tokens and ids are answered
as ones that never existed (spec 03 §13). The clients' forgetting of an earlier account stands on
this. Two limits: a server restored from before the deletion brings the account itself back, and a
server that is not honest can serve anything under any id, which the device's record of the
account's identity key is there to catch (T1).

**A14 (security review 2026-10, whole-repository scan of 0.28.1).** (a) **The escrow ceremony keeps the seed out of
docker's logs** (F1): `bringup.sh` (since replaced by `andvari setup`, design 2026-11-15 §9.5) and every documented `docker run … recovery-cli` pass `--log-driver none` before the
image, because docker copies an attached container's stdout to its log driver (json-file on disk, which `--rm` only
unlinks; the journal; a log shipper). What stays: the sheet in the terminal's scrollback (the script says to clear it)
and the air-gapped keygen as the by-the-book ceremony. A dated design record that sketched the ceremony as `docker
compose run` is left as written; nothing ships that form. The deploy test scans `deploy/`, `docs/`, the `Dockerfile`,
`.github/` and every other repo-root file for the command (the Dockerfile's own header example had missed the flag until
the A14 review, W6). (b) **`/data` is owner-only** (F10): the entrypoint makes it 0700 after its chown, tightens
existing database files to 0600 and starts the server under umask 077; `bringup.sh`, while it shipped, created `./data` 0700. A chmod that
fails (a read-only or root-squashed mount) warns and the server still starts, as root or not (A14 review Wd). The server
is the only reader of the database; a host-side backup runs as root, and under rootless docker as real root or the
subordinate uid the container's user maps to. Residual accepted: `users.totpSecret` is stored in plaintext in the
database (encrypting it at rest is not built), so anyone who reads the file, now root or the container's user only,
reads every member's TOTP seed.
(c) **One sender gate in the extension's service worker** (F3/F4/F11): every message type is classified as sent by
content scripts (the 17 types `content.ts` sends) or extension-page-only; the other 27 are answered with their own
refusal shape unless `sender.url` is one of this extension's pages (`chrome.runtime.getURL("")`, either engine; a
malformed base fails closed), before the handler runs, and a refused message does not re-arm the idle lock. `status`,
`ping`, `updateStatus` and `linkUri` are gated too: no content script sends them. Unknown types are refused. The
per-handler checks stay. Residual: a compromised RENDERER of one of our own extension pages is outside this gate (it is
the extension). The gate covers messages only: until A15, storage.local was a second way in (the worker adopted a
`serverUrl` written there and linked a stored update offer), which A15 closed. (d) **The CSV formula warning is an acknowledgement** (F6) on web, desktop and Android: it names each
risky cell by field and item ("Password of “…”", the name escaped onto one line after our label), and the save stays
disabled until it is ticked for exactly those cells. Values are written verbatim, by decision: a CSV export is input for
another password manager, and a `'` prefix would corrupt a real password that starts with `=`, `+`, `-` or `@`. Since
the A14 review (N3) the native writes re-check it against what they write: the vault is re-read after the file chooser
and a sync can land in between, so desktop and Android recompute the cells from the docs actually written
(`ExportCsv.gatedWrite`) and write only when the tick covers exactly them; otherwise nothing is written and the dialog
comes back with the new list, the same vault selection and an empty tick (web writes the very items the render that
enabled its button computed). (e) **An enroll is bound to the origin its client dialed** (F8, desktop and the reachable
Android twin): while it runs, Cancel, a re-pasted invite and Connect are refused and disabled; the session is saved
under the client's own origin, and if the app was moved anyway the commit is aborted and the tokens revoked at the
issuer; a stored session's tokens go only to its own origin (unlock refuses another; a locked sign-out revokes at the
session's origin and still wipes locally). Since the A14 review (N4), a sign-in is bound the same way on both apps: its
client's origin is captured when the client is built, the session is saved under it, and a move during the login and KDF
aborts the commit with a revoke at the issuer; and desktop's manual repoint (`updateServer`, the gate's Connect) is
refused at the state layer while any op holds a client, not only by the dialog's disabled button. Residuals: a session a
pre-A14 build already saved under the wrong origin cannot be told apart from a correct one; an install whose saved
session predates the one-time default-URL migration now signs in again once. (f) **Desktop secret copies are marked
sensitive** (F9): Windows `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory` and
`CanUploadToCloudClipboard` (each a DWORD 0; the first was an empty payload until the A14 review, N8, which AWT
publishes as a zero-size global block that may be a discarded handle), KDE `x-kde-passwordManagerHint` = `secret`; the
auto-clear stays. Residual: a clipboard manager that ignores these hints still records the copy (owner device check:
Win+V and Klipper on a real desktop). (g) **The offline tools escape
what they print** (F12): `backup-cli verify` and `recovery-cli verify` replace every C0 (tab and newlines included), DEL
and C1 character in payload-authored strings with a visible `\u001B`-style escape, the drill receipt line by line
(JSON's own escape, so it still decodes the same). Since the A14 review (Wc/N9) the same escape also covers
U+2028/U+2029 and the bidi controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), which a renderer would take
as a line break or a reordering, in core `TerminalText` and in web's CSV-cell labels alike. Residual: `backup-cli dump`
relies on JSON escaping, which leaves C1 and the bidi controls raw.
(h) **A browser without the offline copy keeps no token once locked** (F5, owner decision): unless the offline copy is
on for the user on this browser, the token pair lives in sessionStorage per tab (localStorage keeps the non-secret
metadata, whose removal is the cross-tab sign-out signal); a lock (manual, idle, or announced by another tab) awaits the
vault's usage flush, revokes the tab's pair and drops it, and unlocking is then a full sign-in (email filled in, master
password, one-time code when enrolled); a pre-A14 pair on disk moves into the tab at load; turning the offline copy on
or off moves the pair between the stores at once. With the offline copy on, nothing changes. Tabs: a tab with no pair
signs in as its own device session, so tabs never share a rotating refresh token and no token hand-off channel is added;
a duplicated tab (which inherits a copy of sessionStorage) is detected by a per-tab Web Lock and drops the copy; a tab
riding the shared pair when another tab turns the offline copy off locks without revoking. Since the A14 review: a
per-tab lock records its own revocation of the pair it dropped, and a later sign-out with no pair left in the client
reports that result instead of POSTing a logout with no token (which 401'd and raised "the server didn't confirm" on
every sign-out after a lock); a lock whose revocation the server did not confirm says so on the unlock card (W1); since
the third A14 review that result is also kept in the tab's sessionStorage (`pending` until the server answers, which a
reload reads as unconfirmed), so a sign-out after a reload or in a new App instance still reports a refused lock-time
revocation instead of "confirmed" (W-b). A
refresh already in flight when the pair is dropped or replaced adopts nothing (a generation counter in the client), so a
lock is never undone by a rotation landing after it (W2). A login or register pair is held in memory and written only by
the caller's saveSession, with the new account's metadata: the client is rebound to the account the server answered for,
so a tab that booted to Welcome for X never writes Y's pair under X's metadata, even if Y's sign-in then fails or the
pair rotates first (W3). Since the third A14 review the client is bound to the server's userId only after
`Account.unlock` has accepted the keys that came with it; between login and unlock it is bound to a fresh random
placeholder no account has, so a rotation in that window is written nowhere and nothing persisted is adopted, even when
the server names the account whose metadata the tab holds (W-a). A sign-in that fails after login() (unlock refused the
keys, the first sync failed) revokes the new device session's pair and drops it, instead of keeping it live in the
tab's memory until the next sign-in replaced it. A sign-out in another tab, without the offline copy, revokes this tab's own pair before
dropping it (W4). An unlock card that still holds this tab's pair (a reload of an unlocked tab) runs the policy idle
timer and takes the per-tab lock when it fires (W5). The lock's phase change runs in a finally and the session's storage
writes are guarded, so a write that throws can no longer leave the vault open (W7). Turning the offline copy ON in one
tab revokes another tab's own per-tab pair before that tab adopts the shared one (We). Residuals: a reload keeps the
tab's pair (sessionStorage survives it), so a reload of an UNLOCKED tab is a master-password unlock, not a sign-in, now
bounded by the idle timer; sessionStorage is not guaranteed off disk — Chrome and Firefox write it into the profile's
session-restore data for crash restore, "continue where you left off" and reopen-closed-tab, so an unlocked tab's pair
(a locked tab holds none) can sit in those files while it is valid and comes back with a restored tab, and anyone who
can read the profile can read it then (Wb, the "never on disk" comment corrected); the transition from a pre-A14 bundle:
a tab still running the old bundle keeps writing the pair back to localStorage until it is reloaded, and an old tab and
a migrated tab that spend the same refresh token trip the server's reuse check and revoke the device once (We); without
Web Locks a duplicated tab cannot be told from a reload and keeps the copy (and the first refresh of the pair by both
then revokes the device, the failure the guard exists to stop); script on the origin can still read the open tab's pair.
(i) **Package-only app fills are gated** (F7, owner decision,
Android): an `androidapp://` login fills silently only into a system app, a Play-installed app (`installingPackageName`,
`getInstallerPackageName` on API 29), or a (package, signer) this device confirmed; anything else, or any failed lookup,
gets a one-tap confirm naming the app, package, installer and signer (short form), and a changed signer confirms again
with a warning. Identity is read from PackageManager in andvari's process and baked into the confirm's PendingIntent.
Since the A14 review: the manifest queries every launcher app (`MAIN`/`LAUNCHER`) and the Play package by name, because
the autofill framework gives a service no visibility of the requesting app and on API 30+ every lookup used to throw
(lead finding); "Play-installed" means the recorded installer is named `com.android.vending` AND is itself a system app,
so a sideloaded app that took that name on a device without real Play does not count (N1; no Play signing-digest pin,
because no authoritative public digest was found to pin, and a guessed one would only push real Play installs to the
confirm); the confirm shows the app label and the installer label as one escaped, bounded, single-line text after the
platform's `makeSafeForPresentation`, names the installer's package and whether it is a system app, and names the login
(item and username) it would release (N2); the installer's package and kind are a line of their own that leads and is
never ellipsized, and the installer's label is a separate line, so no label length can push "NOT a system app"
off-screen (third A14 review, A1); touches through another window are dropped (`filterTouchesWhenObscured`),
other apps' overlays are hidden on API 31+, and the button accepts a tap only half a second after the window gained
focus (N6); the live signer, installer, installer kind and system flag are re-read at the tap and a change refuses the
fill, and the (package, signer) is remembered only when a fill was delivered (N7). Bindings are device-local, never
synced, excluded from cloud backup and device-to-device transfer (N5), and cleared on every path that ends the session
(sign-out, a definitive 401, a revocation purge, a refused refresh, a server switch, another account saved over this
one). Residuals: the installer field is what PackageManager recorded, so an installer able to record another package (a
privileged shell, `adb install -i`) can pass as Play while the real system Play is present, and `initiatingPackageName`
is not consulted; on a device where Play is a user app (sandboxed Play on GrapheneOS) every Play install takes the
confirm; an app with no launcher activity stays invisible to andvari, so its fills always confirm and are never
remembered (owner device check); the host app holds each confirm row's IntentSender and can fire it again, which only
reopens the confirm; card datasets are not app-gated (wallet posture, unchanged). **Superseded 2026-11** for every app
that is not a verified browser: see "Autofill (client-side, Android)", the 2026-11 review, (a) and (b).

**A15 (security review 2026-10, the extension's storage, from the A14 review's Wa note).** Platform facts, which set
the shape of the fix. Content scripts can read and write `chrome.storage.local` and receive its `onChanged` events. On
Chrome that is the default: "By default, it's exposed to content scripts, but this behavior can be changed by calling
`chrome.storage.local.setAccessLevel()`" (https://developer.chrome.com/docs/extensions/reference/api/storage), and
`setAccessLevel` covers `local` only from Chrome 140; before that it exists for `session` alone
(https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/storage/StorageArea/setAccessLevel). On
Firefox it is by design: there is no `setAccessLevel` (bug 1724754), and "a compromised content process can read/write
any extension's storage.local" was closed as invalid, with origin-bound storage such as IndexedDB as the advice
(https://bugzilla.mozilla.org/show_bug.cgi?id=2018494). A compromised renderer cannot read or write another origin's
storage, IndexedDB included, and a content script runs in the web page's origin, so the extension origin's IndexedDB is
out of its reach on both engines
(https://chromium.googlesource.com/chromium/src/+/main/docs/security/compromised-renderers.md). The precondition is
A14's F11 (code with content-script privileges, i.e. a compromised renderer), and before A15 it got past the A14 sender
gate through storage: a `serverUrl` written to storage.local repointed the extension with no Trust Gate (the worker
switched on `onChanged` and adopted the value at every start), and a stored update offer put an unverified "Download &
reload" link into the popup (MEDIUM each); planted item homes hid items from fill (LOW).
(a) **The update link has one shape** (step 0): `${DEFAULT_SERVER_URL}/downloads/<basename>` (a plain file name: no
slash, dot-dot, query, fragment or escape), only while the current server is the default, whose `/downloads` is what
the pinned key signs. The worker builds it from the verified manifest, re-checks the stored offer on every read
(version, server and both links; `updateoffer.ts`), and the popup checks the link again before it becomes an href.
(b) **The storage areas are restricted at worker start** (step 1): `setAccessLevel(TRUSTED_CONTEXTS)` on
storage.session and, where it exists (Chrome 140+), on storage.local, both awaited before any lock samples the
quick-unlock compartment verdict. That verdict now says what the code saw: on Chrome the session call resolved (a call
that exists and fails leaves the compartment untrusted, so nothing arms); on Firefox, which has no such call, only that
storage.session exists. Since A16 the verdict also needs the session sealing key (below). `minimum_chrome_version`
stays 127. Checked in a headless Chrome 149: once locked, a content
script's storage.local `get` and `set` are refused, where both worked before.
(c) **Durable trust state lives in the extension origin's IndexedDB** (step 2; `trustedkv.ts`), with the service worker
as its only reader and writer: the server choice, the update offer and its anti-rollback seq, item homes, the
personal-wrap cache and a pending personal change, and the conveniences (the remembered email, which content scripts
could read, the biometric credential id, the offer-dismissed flag). The update throttle stamp and quiet
marker are not trust state and live in storage.session. The popup and the options page never touch a storage area or
the store: they ask the worker (`serverInfo`), and the server choice changes only through `setServerUrl`, which the
options page sends after the Trust Gate's Connect and which the A14 gate admits from our pages only (with
`serverInfo` and `forgetLegacyServer`, 30 extension-page-only types now); the worker canonicalizes, writes the store
and runs the origin-clean switch. The `onChanged` trigger is gone. "Remove data for this server" now removes every
record under that origin's namespace in every store, by prefix, including the per-user item homes, personal wrap and
pending change that the fixed key list had always missed although the options copy promised "cached state for that
server". Source fences hold the layout: the content bundle and our pages never name chrome.storage or IndexedDB, and
the worker hands storage.local to three leaves only (the migration, which reads it only when owed; the server state,
which reads its `serverUrl` only with no store and only to block; the purge) and otherwise only removes from it. Since
the A15 review every store operation, the open and the transaction together, is bounded at 4 s and then rejects as
"unavailable, timed out" (S1: an IndexedDB open that never settled wedged worker start and with it every message),
and a transaction whose body throws is aborted (S2: the puts issued before the throw used to auto-commit, so a write
reported as failed had half happened); the quick-unlock co-key database opens under the same bound.
(d) **The one-time migration adopts nothing a web page could have planted, and runs only on the upgrade it exists
for.** Any pre-A15 storage.local value may be planted and cannot be told apart from a real one, so: a non-default
`serverUrl` is NOT adopted; it becomes a pending server ((f) below). The update channel is not migrated (the seq floor
restarts at `MIN_SEQ`; the forced start/install check re-derives the offer). A pending personal change is dropped (the
next unlock re-stages it). Item homes and the personal wrap move under their strict decoders, the same trust they had
(homes are ids the server knows; the wrap is AEAD-sealed under the UVK). The conveniences move shape-checked. Since the
A15 review (F2) storage.local is read only when the browser attested an upgrade from a pre-A15 build:
`runtime.onInstalled` with reason `update` and a `previousVersion` no newer than 0.28.1, the last release without the
store (`LAST_PRE_A15_VERSION`, to be raised should another release without A15 ship first). That event is recorded in
the store as "owed" before anything is read; the flag and the owed mark are swapped in one write when the copy has been
read back and compared, so a migration cut short once "owed" is recorded finishes at the next start (owed alone, no
event needed). That first write is the one thing a later start cannot redo, since the event exists only in that worker
life: when the store refuses it or does not answer, nothing is recorded, so the worker retries it within the same life
(at once, then after 2, 10 and 30 s), and the block stays `unsettled` meanwhile (A16 review R3: before, the next start
then skipped the migration and dialed the default while storage.local still named the self-hoster's server). Every
other start without the flag (a fresh install, an update from an A15 build, a browser update, or a start with no install
event at all) sets the flag WITHOUT reading storage.local, and in the same write a mark that it did so. With the store
holding no server choice, that start then reads storage.local's `serverUrl` ONLY to block, decline-only as in (e): when
it names another server, the worker signs in nowhere and the address is never offered for connecting (the user enters
their server in Options, or chooses "Not mine"), so a planted value is only a denial of service. The origin is kept in
the mark, so later starts block on it without reading storage.local again; it goes when that start finds no other
server named there, when a server is chosen, or on "Not mine" (which also removes the old value). Before F2 any flagless start migrated, so a store that was
unavailable at the upgrade and available later (Firefox's "Never remember history" turned off), or that lost its data
while storage.local kept its own, moved whatever a content script had written there in the meantime (a planted server
suggestion, homes, an older wrap, an email, a credential id); the Options copy "Before an update, this browser was set
to connect to" was then untrue. Worker start waits for the install event at most 5 s, and only while the store holds
neither the flag nor the owed mark (the event arrives right after the worker first runs); an attesting event that
lands after that wait is recorded as owed and migrated then. The migration flag and the owed mark live in the store
only, so a content script can neither skip, re-run nor owe the migration; the old keys are deleted only after the copy
was verified; a value the store already holds is never overwritten. **No store at the attested upgrade** (Firefox
"Never remember history"): there is nowhere trustworthy to record "owed", so nothing migrates, then or ever. The fail
safe is (e)'s block, and once the store is available again the first start sets the flag without reading: the device
is on the default server with nothing migrated (a fresh install's posture) and the user enters their server in Options.
(e) **No IndexedDB means safe defaults, never storage.local for trust.** Firefox blocks IndexedDB for extension pages
in private browsing, and under permanent private browsing ("Never remember history") that includes the background page
(bug 1841806, Firefox 117, 116.0.3 and ESR 115.2; https://bugzilla.mozilla.org/show_bug.cgi?id=1841806; an extension
page in a private window cannot open it either, which is one reason the pages ask the worker). There the extension can
keep no server choice: Options says why and refuses a switch rather than pretend. The default server is the only one
in effect, except that since the A15 review (F1) storage.local's `serverUrl` is read at each worker start ONLY to
block: when it names another server, the worker signs in nowhere and the popup says the previous server cannot be kept
in this mode (turn the setting off, restart, enter the address in Options), with "Not mine" (which removes that old
value) as the way to the default. It is never adopted and never offered for connecting. Item homes are kept for the
browser session (in the session snapshot), the personal vault is asked for at each unlock (the staged choice is held in
worker memory, and an accepted one applies to that session), there is no update banner (a failed seq read ends the
check before anything is fetched; Firefox's own `update_url` still updates the add-on), and no email is remembered;
quick unlock already did not work there (its co-key is in IndexedDB).
(f) **A pending server dials nothing, the default included** (A15 review F1). Before the review the worker dialed
DEFAULT_SERVER_URL while a migrated server waited for its confirm, with nothing stopping a sign-in. The update clears
storage.session, so the user signed in again, the email prefilled, and the reference instance, which answers an unknown
email with a deterministic fake salt, received the email and an authKey derived from the master password under a salt
it chose (an offline-guessable verifier at the KDF floor). The update channel polled it, the open-vault, forgot and
must-change buttons opened it, and the self-host vault UI lost its autofill exclusion. Now, while a server is pending
(`serverstate.ts`): every sign-in lane and the connection test (`unlock`, `unlockTotp`, `unlockWithPin`,
`unlockWithBio`, `ping`) are answered `confirm_server` right after the sender gate, before any handler; the update
check returns before it fetches; and since the A16 review (R4) nothing else dials either: the worker's api refuses
every request (a hydrated session's sync and saves, a token refresh, the socket's ticket), the resync and the socket do
not start, and a sign-out wipes locally without its revoke; the pending origin's match pattern joins the autofill exclusions, and an origin that
cannot be written as one (a bracketed IPv6 literal) means no autofill at all (excluding a planted origin is harmless);
the popup shows the confirm route INSTEAD of any sign-in form ("Before this update, andvari was set to use: …",
"Confirm in Options" first, "Not mine — use <default host> instead" second), its header names no server, and no server
page opens. Only the Trust Gate's Connect (`setServerUrl`, after the choice was kept) or "Not mine"
(`forgetLegacyServer`) lifts the block; the pending state is read from the store at every start, so it survives
restarts. The same block, `unsettled`, stands when the store did not answer in time or an owed migration did not
complete: the worker cannot tell which server the user chose, so it signs in nowhere, registers no autofill (the
user's vault origin is unknown) and says so (the next worker start retries). A later re-read of the store in the same
worker life (a late install event, the retried owed write) never moves the dialed origin, so when it names another
origin than the one the worker dials, the block stays `unsettled`. A page that gets no answer from the worker
opens nothing and shows no origin (S3: before, it fell back to the default, and a click opened the reference instance).
Checked in a headless Chrome 149 over the pre-A15 build's profile: after the update, the five dials were refused with
no request to any server (an update poll and a prelogin to the default on the build before the review), the pending
origin was excluded from autofill, the popup showed the confirm card, the block survived a restart, "Not mine" lifted it
(a ping then reached the default), and a store wiped while storage.local held a plant migrated nothing.
(g) **The rest of the review.** F3: the anti-rollback seq is read with the store's own `get` before the fetch, and a
failed read ends the check (before, a read error folded into the `MIN_SEQ` floor and a verified manifest could then
write a lower seq). S1: a lock never waits on the store beyond 1.5 s: the popup's Lock skips the general load, and
`doLock` waits for the origin (whose namespace its arm and wipe land in) at most that long; a healthy store answers in
milliseconds, so a cold idle lock still arms. Past the bound it erases the session snapshot first, keeps only the tab
records' page-known half, arms nothing and wipes no quick-unlock record (the current namespace is unknown; an enrolled
record stays unarmed, so the next unlock is a full one), and a load that read the snapshot before that erase does not
hydrate it. The autofill registration also reconciles one call at a time now: worker start and the install event both
reconcile on an update, and two overlapping runs made the second register fail on a duplicate id and, failing closed,
unregister the first (no autofill until the next worker start; seen in the live check).
Residuals: (1) Chrome 127–139 and Firefox: storage.local stays open to content scripts. The extension reads it for trust
only during the attested migration, so what is left is the window before the upgrade: values planted then move with the
trust they always had (homes, the wrap, the conveniences), and a planted server only ever becomes a pending server. On
Chrome 140+ the area is locked, and the level is kept in the extension's prefs across restarts. (2) A15 left
storage.session as it was: on Firefox, its exclusion of content scripts was relied on for the session snapshot and the
armed quick-unlock record. Since A16 it is not relied on (below). (3) A server planted before the
upgrade is shown as the user's previous server, and "Confirm in Options" is the popup's first button; the Trust Gate
still shows the raw origin and Connect is still the only commit. (4) Firefox permanent private browsing loses the
self-host choice and the remembered state across restarts, as (e) says; a value a content process plants in
storage.local there blocks sign-in until "Not mine" (a denial of service, never a repoint); and turning the mode off
lands on the default server with nothing migrated and no pending server, so a self-hoster must re-enter the address
(the popup's header shows the default's origin, and the earlier block told them to). (5) `LAST_PRE_A15_VERSION` is a
release fact: if a release without A15 ships after 0.28.1, an update from it to A15 attests nothing and migrates
nothing (the fail-safe direction: no read, the default with no pending server). (6) A session that hydrates in a
worker life where a block stands — from a sealed snapshot of the dialed origin, when the trusted store did not answer
but the seal's key did (`unsettled`), or in the no-store mode, where the block is recomputed at each start — stays
unlocked on this device and serves what it holds, but dials nothing until the block is lifted (no sync, save, refresh,
socket or revoke); signed out meanwhile, it is wiped locally only, and its refresh token stays valid server-side until
it expires or the device is revoked. (7) The unattested block (d) rests on storage.local at the one start that skips
the migration: a content process that deletes the old value before that start (after an attested upgrade whose "owed"
write failed, and was not recorded by the retries within that worker life) leaves no block, and the default is then the
server, as in the no-store mode (4); one that plants a value then gets a denial of service until "Not mine". After that
start the origin is kept in the store, and storage.local no longer moves it. If the write of the flag and the mark
fails, the next start skips again, reads again and blocks again.

**A16 (security review 2026-10, sealed custody in storage.session).** The extension keeps unlocked custody in
`storage.session` on both engines, because the worker is stopped when idle: the session snapshot (tokens, unwrapped
vault keys, decrypted items), the tab records (a pending save holds a page's password in plaintext, also while locked),
the armed quick-unlock record (the PIN-crackable UVK blob and a live refresh token) and the known-logins digest (an HMAC
key beside its digests). A compromised content process is in the model (A14's F11, A15), and that a content script
cannot reach `storage.session` is no longer relied on: Firefox's exclusion of content scripts from it is not relied on,
and Chrome's browser-side enforcement is kept as a second layer. The boundary relied on instead is the extension
origin's IndexedDB, which a compromised renderer cannot read or write
(https://chromium.googlesource.com/chromium/src/+/main/docs/security/compromised-renderers.md), and which Mozilla
names as the origin-bound storage to use (https://bugzilla.mozilla.org/show_bug.cgi?id=2018494). Memory-only custody
was not an option: Firefox stops the event page after about 30 s idle, and the vault would lock every time. The seal
is not a lock (spec 01 §8.4 rejects a key-beside-ciphertext lock): a lock still erases; the seal keeps what
`storage.session` holds from anything that can reach that area but not the extension's IndexedDB.
(a) **One sealing key per browser session, replaced on the browser's word** (`sessionseal.ts`): a non-extractable
AES-GCM 256 key in its own IndexedDB database (`andvari-session-seal`, apart from the quick-unlock co-key and the A15
trusted store), every operation bounded like the trusted store's (4 s). When the browser reports a new browser session
to the worker — `runtime.onStartup` (a browser start) or `runtime.onInstalled` (an install, an update, a reload, a
browser update), events a web page cannot raise — every sealed record is dropped and a fresh key replaces the old one.
No session can exist at that point, so whatever the worker hydrated, read or was writing before the report in that
worker life is dropped too, never armed: a load in flight installs nothing, a write issued before it is not written, a
read reads absent, a quick-unlock record read before it is not written back. At any other worker start the stored key
is kept only if a record in `storage.session` opens under it (in its own slot, for its origin, under the stored epoch);
otherwise — no record, garbage of the right shape, another key's records, copies from before a lock — every sealed
record is dropped and a fresh key replaces the old one. Before the A16 review a record's shape was enough to keep the
key, so a planted `{v:1, iv, ct}` kept it and, with it, a copy of the previous browser session's records openable (R1).
What holds: once the worker has handled a browser session's report, nothing sealed before it opens again; a start with
no report keeps the key only for records sealed under it. What does not: residual (7).
(b) **Every secret-bearing record is sealed, through one helper**, and stored as `{v:1, iv, ct}`. The AAD binds the
record kind and the origin namespace, so a record copied into another record's slot, or into another origin's slot,
does not open. The session snapshot and the tab records are also bound to a custody epoch that every lock advances and
that is kept beside the key, so a copy taken while unlocked does not open after the lock, a worker restart included. A
record that does not open (no key, another key, tampered, swapped, from before the last lock, or plaintext) is
absent, which reads as locked, and it is dropped; it is never adopted. The inventory: sealed — `session`, `tabs`,
`ns.<origin>.quickUnlock`, `ns.<origin>.knownLogins`; plain, as none is secret — `lockNotice` (the idle-lock reason
line), `ns.<origin>.updateCheckedAt` (the update-check throttle stamp) and `ns.<origin>.updateChannelQuiet` (a quiet
reason from a fixed set); a write to one of those can at most show a false reason line or move an update check, and the
forced check at start re-derives the last two. The worker reaches `storage.session` through two wrappers only: the
seal, and a plain area that refuses any other key when called. A source fence holds every write to them.
(c) **Migration.** At worker start a plaintext value in a sealed slot (the previous build's, or anyone's), the
pre-namespacing bare quick-unlock key and any key this build does not keep are dropped, never unsealed into trust. The
cost is one more unlock after the update, and the update clears `storage.session` anyway.
(d) **No key store** (no IndexedDB, as under Firefox's "Never remember history", or no answer within the bound): no
secret-bearing record is written to `storage.session` (a write removes the slot instead, so no older copy stays);
custody stays in worker memory, so a stopped worker means a locked vault; quick unlock does not arm, and enrolling it is
refused with a sentence that says why. The Options note for that mode says the vault locks whenever the browser pauses
andvari. The next worker start tries the store again.
(e) **The quick-unlock compartment verdict** (`quCompartmentTrusted`) now means that the sealing key is available,
and, on Chrome, that `setAccessLevel(TRUSTED_CONTEXTS)` on `storage.session` resolved (kept as a second layer). It gates
arming, enrolling, and keeping the known-logins digest across a lock.
(f) **A lock never waits to erase.** Its first act, before it awaits anything, removes the snapshot and the tab
records, advances the epoch in memory and drops the in-memory session, keeping in the same step a copy of the two
records as they stood (ciphertext); a sealed write still in flight for them is dropped, and a load in flight installs
nothing it read. Only then does the lock wait, at most 1.5 s, for the origin and the key (A15 review S1), and it decides
the quick-unlock arm from what stood at the lock: the live token pair or, in a worker that had not loaded the session
yet, its own copy, opened under the epoch it was sealed in (it keeps the tab records' page-known half the same way).
Without the origin and the key in time it arms nothing, wipes no quick-unlock record and keeps no tab record. Before
the A16 review a cold lock waited up to those 1.5 s before it erased (R4). A sign-out is that lock, then the server
revoke on the pair the lock saw (before, it waited on a load and on the network, up to 7 s, before erasing); it waits
up to 5 s for the origin and the key, after the erase, and one that gets neither wipes locally only. After the
erase the lock waits, at most 1.5 s more, for the new epoch to reach the key store; a write that failed is retried by
every later seal operation in that worker life; and the snapshot and the tab records are written only under an epoch
the key store holds (held until it does, and not written at all while it refuses, so custody stays in memory), so no
later start reads them under an older epoch and opens a copy from before the lock. A lock in a worker life with no key
store is recorded against the stored key if the store answers later in that life. Before the review a failed epoch
write was never retried, and a lock that ran before a failed start lost its advance (R2).
Checked in a headless Chrome 149 against a local server: after a full unlock `storage.session` held only sealed
records (no item name, email or password in it); a worker stopped and restarted stayed unlocked; quick unlock armed at
the lock, survived a restart and redeemed with the PIN; the snapshot copied before a lock and put back after it did not
open (the restarted worker stayed locked and dropped it); a plaintext snapshot planted while locked was dropped at the
next start. After the A16 review, also: a lock sent to a stopped worker (nothing had loaded the session) erased at once
and still armed, from its own copy; with only a sealed-shaped garbage record left in `storage.session`, a restarted
worker replaced the key, and a copy of the armed quick-unlock record planted after it did not open (on the build before
the review it armed again); and a browser restarted while unlocked came back locked, its IndexedDB intact, and the
previous browser session's sealed snapshot planted afterwards was dropped unopened.
Residuals: (1) custody in worker memory is still exposed to a compromised extension process: the worker holds the
unlocked vault and the key's handle. (2) Chrome's browser-side enforcement of the `storage.session` access level is
now a second layer, not the only one. (3) The quick-unlock record and the known-logins digest survive a lock by design,
so they are not bound to the epoch: a party that can both read and write `storage.session` can put back an older sealed
copy of either, which restores an earlier attempt count (already accepted, A7-extension (b)) or an earlier digest. (4)
The epoch lives only in the key store. If the worker stops, or the store keeps refusing, before a lock's epoch lands —
or a worker life has no key store at all and the store does not answer later in it — a copy of the snapshot from
before that lock still opens at the next start. (5) A sealed record is about a third larger than the plain one
(base64), against the area's quota. (6) Replay within one epoch: with no lock in between, a party that can read and
write `storage.session` can put back an older copy of a record sealed under the current key and epoch — the snapshot
(with a refresh token since spent, which the server takes for token reuse and answers by revoking the device: a
denial of service), the tab records (a pending save already resolved, a stale top origin for a tab's badge), and at
any time the records of (3). Nothing opens that was not sealed under the current key and epoch, and no secret leaves;
binding a per-write counter would need a key-store write beside every `storage.session` write. (7) A browser session
the worker is not told about: the extension does not rely on `runtime.onStartup` reaching its background (it may not,
for an event page), and a message can wake the worker before the report is handled. Until the report is handled, or
for the whole browser session where none comes, the key is kept on the start rule alone, so a party that can write
`storage.session` before the worker's first read in the new browser session can put back a copy sealed in the
previous one, and it opens: a snapshot from a session that ended unlocked (the vault opens without the password, until
the report drops it), or an armed quick-unlock record (the PIN and the co-key are still needed, within its 24 h). A key
store that refuses the replacement at a report leaves the old key in place (the worker deletes it where it can) until
the next report, or a start where nothing opens under it.

**A17 (2026-11: keys after a lock; spec 01 §8 "Keys in memory and the lock").** **The fault.** In the
app engine a lock erases the account's keys in place, and work that outlived the lock went on using the arrays it
had erased: an import whose batch was on its way, a save waiting behind a sync or an upload, a password change, a
device-link approval and an account-state update could seal, wrap or sign under a key of zeros after the lock and send
the result. What was sent read as sealed to the server and to every other device, and was under no key at all; one
path read the lock as an unreadable account state and would have sealed an empty one under the zero UVK over the real
one. No released version had it: the engine that had it is in no release, and the released clients erase no key at a
lock. **What enforces the rule now:** (a) **the guard** (spec 01 §8 rules 1 to 3): every key of an opened account is
lent to one block that cannot wait, and no copy of a key leaves the guard; an answer that is the key, a copy of it
or its text is refused where the test machinery is on (the suites the tripwire watches, (c) below), a development check and not a rule of
the running product: a shipped build hands back what the block answered and never compares it with the key, zeroes it
or refuses it, because data can equal a key (any member of a shared vault knows its key, so its owner
can name the vault with the key's text, and refusing that name would stop every other member's device); a lock erases
under the guard, so a running use finishes on whole keys and none starts after; and work
checks the guard after every wait before it seals, signs, derives or sends. (b) **The refusal of all-zero keys**
(rule 4): the shared crypto path refuses a seal, open, wrap, signature, derivation, grant or MAC under an all-zero
key before the provider is called, as a lock and never as a wrong key. (c) **The tripwire over the test suites:** in
test runs only, a watcher on the crypto provider records every seal, open, signature, key pair, derivation and MAC
under an all-zero key that reaches the provider, and every refusal of rule 4, including one a handler swallows; a test
task fails at its end on any record not made by a reviewed list of tests that feed zeros on purpose. It watches core's
JVM tests, the hostile-server harness, `andvari-cli`'s, the recovery tool's and the backup tool's tests, the server's
tests, and the desktop's and the Android app's unit tests. A release carries only the seam it is found through, and no
watcher. (d) **The source check** (`AccountKeyFenceTest`): the account's key fields are guarded types, a guarded array
is read only inside its guard, every lend's body (wherever its first line starts) is read for an answer that is the
key, a copy or its text and for an assignment, `add` or `put` of one, and no shipped source copies a key out of the
guard (quick unlock's enrolment included: spec 01 §8 rule 7). Probes run each overtaken case against a server that
holds the route until the lock lands (`EngineKeysAfterLockTest`), each wait bounded so that a hang fails. **What these
do not stop:** a key handed to a helper that keeps the array, or wrapped in an object of the block's own making, passes
both the refusal in tests and the source check (and a shipped build inspects no answer at all); it is caught only when
it is used after an erase, where rule 4 refuses it (and a test run records it). A helper that keeps a *copy* is not
caught at all: a copy is not zeroed by the erase, so neither rule 4 nor the tripwire sees its use after the lock. The
tripwire sees only what the watched suites run; core's Android and iPhone tests are not watched. **The TypeScript clients** (the web client and the extension) erase no key at a lock,
so they cannot seal under an erased one; the cost is that their keys stay in memory until the garbage collector frees
them.

## Quick-unlock at-rest secret (A7, Android — spec 01 §8.1)

Enabling quick unlock changes the at-rest story of exactly one asset: a
Keystore-wrapped copy of the UVK now persists on the device. What each attacker
gets:

| Attacker | Outcome |
|---|---|
| **Device in hand, UNLOCKED, vault app locked** | Can *see* the biometric-unlock offer but cannot pass `BiometricPrompt` (BIOMETRIC_STRONG / Class 3 — spoof-resistance per the Android CDD; screen PIN/pattern deliberately NOT accepted, spec 01 §8.1). The honest **narrowing vs T3**: where a stolen device previously required the master password, it now falls to the owner's biometric — a sleeping/coerced owner or a Class-3 sensor bypass is the new (accepted, opt-in) exposure. Coercion is out of scope, same as for the master password. An OPEN vault remains T4. |
| **Device powered off / locked (thief, border search of hardware)** | The blob is AES-256-GCM ciphertext under a non-exportable TEE/StrongBox key with `setUnlockedDeviceRequired(true)` — unusable before first device unlock. No offline brute-force surface exists: the wrapping key never leaves hardware, and the blob without it is just 32 random-looking bytes plus tag. Chip-level key extraction is nation-state class (Non-goals). |
| **Malicious app on the device (non-root)** | App-sandbox private file (`noBackupFilesDir`); Keystore keys are per-UID — another app can neither read the blob nor request the cipher. Fake-overlay biometric phishing yields nothing: the prompt is bound to OUR key's `CryptoObject`. Root/accessibility malware is T5, out of scope — and quick unlock does not *worsen* T5 (unlocked-process memory already holds the UVK; a keylogger already gets the master password). |
| **ADB / backup extraction** | `android:allowBackup="false"` + the blob and cache both under `noBackupFilesDir` ⇒ neither `adb backup` nor cloud backup carries the blob; a leaked blob alone is useless without the hardware key (above). ADB shell as the app's uid implies a compromised/debug device — T5. |
| **The server** | Learns nothing — quick unlock is wire-invisible (spec 01 §8); the server story is unchanged (T1 unaffected). |

Residual accepted: the `lastFullPasswordUnlockAt` freshness stamp is advisory
plaintext — resettable only by an attacker already inside the app sandbox (T5),
who still cannot use the Keystore key. The A5 risk of *forgetting* the master
password behind a working biometric is bounded by the normative 30-day periodic
full-password rule (spec 01 §8.1).

## Quick-unlock at-rest secret (A7-extension — spec 01 §8.4)

The MV3 extension's quick unlock (spec 01 §8.4) has a **different** A7 posture than
Android's: **non-durable but hardware-less**. Enabling it puts a PIN-wrapped,
session-scoped UVK blob (`ct = AEAD(K_pin, AEAD(K_nonexp, UVK))`) **plus a live
refresh token** in `chrome.storage.session` (memory-backed, sealed since A16 under a
non-extractable key in the extension origin's IndexedDB, gone at browser exit), and
the non-extractable co-key `K_nonexp` in IndexedDB. What
each attacker gets:

| Attacker | Outcome |
|---|---|
| **Device powered off / browser closed (thief, border search)** | Nothing quick-unlock-specific: `chrome.storage.session` is memory-backed and **evaporates at browser exit**, so the blob, counter, and retained token are simply gone. **Strictly better than A7-android vs a powered-off device** (no durable blob at all). Residual: OS **swap / hibernation** may page a memory image (blob + token) to disk — the co-key mitigates data-exfil of the blob alone but not a full RAM/swap image; ⊆ T7 for a disk that also holds the swapfile. |
| **Human-at-keyboard opportunist, browser running, extension locked-armed** | The in-scope delta. Where a locked extension previously required the master password, it now falls to a **6+-char PIN, 5 attempts, then wipe**. This is the accepted, opt-in narrowing. The attempt counter is same-compartment and **attacker-resettable** (below), so against a *sophisticated* local attacker it is theater; against the opportunist it holds, and the PIN entropy floor + session scoping are the real bounds. |
| **Malware / debugger reading the browser process or `storage.session`** | **T5, out of scope** for every client (a keylogger already gets the master password; unlocked-process memory already holds `vaultKeys`). Such an attacker gets a **PIN-crackable blob (double-wrapped: ~32 MiB+ Argon2id over a ≥6-char / ≥10-digit PIN ≈ GPU-hours for a floor PIN, more for a word) *plus* a live refresh token** — but note the blob alone is useless without the **non-extractable co-key** (A1): a pure `storage.session` dump cannot open it. **Per-extension storage isolation is a PLUS**: a co-installed extension cannot read another extension's `storage.session` except via a `chrome.debugger` grant or OS access (both T5). |
| **Co-installed page / content script** | No access: the PIN UI and enroll are **popup-only** (`chrome-extension://`), there is no `externally_connectable`, and arming requires the session sealing key (A16; spec 01 §8.4): the record is AES-GCM ciphertext under a non-extractable key in the extension origin's IndexedDB, which a content process cannot open, so that it cannot reach `storage.session` is not relied on. On Chrome the `TRUSTED_CONTEXTS` level is also set and awaited, a second layer. A page can neither send the PIN nor read the blob; a party that can write `storage.session` can put back an older sealed copy of the record (residual (b)). |
| **The server** | Learns nothing — quick unlock is wire-invisible (spec 01 §8); no new endpoint/header/field. The one wire *interaction* is that a redeem forces a `POST /auth/refresh` FIRST, so revocation / a rescue (which revokes sessions) takes effect at the next redeem (T1 unaffected). |

Residuals accepted (A7-extension): (a) **memory-backed ≠ never-on-disk** — OS
swap/hiberfil can page the blob + token; the co-key defends data-exfil of the blob,
not a full RAM/swap image. (b) The **attempt counter, freshness stamp, and pinParams
are same-compartment and attacker-resettable** by a `storage.session`/DevTools write
(= T5; since A16 such a write can no longer forge them, only put back an older sealed copy) — they defend only the unsophisticated opportunist; a **pinParams ceiling**
still bounds a planted-params OOM, and a sub-range set is treated as corrupt → wipe.
(c) The whole in-scope delta reduces to the **human-at-keyboard opportunist on an
unlocked machine with the browser running**; a machine that is unlocked with the
browser running is already adjacent to T4/T5. The A5 risk of forgetting the master
password behind a working PIN is bounded by the **min(browser session, 24 h)**
periodic-full-password rule (spec 01 §8.4).

## Desktop kept sign-in (T3 — the key store)

With "keep me signed in" on, the desktop keeps the engine's session record in `secure-state.json`: the access and
refresh tokens, the ids, and the account's served keys (ciphertext and public values; no key, UVK or password). The
file is sealed with AES-256-GCM under a random 32-byte key of its own; the operating system's key store keeps that key,
and the file carries only the store's handle for it. The seal binds the store, the handle, the account and the server,
and this computer records which account and server it last sealed for, so a file made for another account or server
does not open here. What the wrap protects is a copy of the file that leaves the computer without the key store's
secret: a backup of the file, a disk image read elsewhere, another account on the same computer as far as the platform
separates accounts. A copy taken together with the key store's own data (a whole-profile backup) is only as strong as
that store's own protection. The wrap gives confidentiality at rest, not integrity: a program running as the same user
can write a wrapped file of its own, and whoever can write the app's folder can also write its settings. The key is
one per file, reused across writes, and the seal carries no counter, so on every platform an older copy of the file for
the same account and server opens in place of the newer one: the wrap does not stop a roll-back.

**Windows.** The store is Windows data protection (DPAPI) for the signed-in Windows user (`CryptProtectData` without
the machine flag, no prompt). The key's DPAPI blob is the handle, inside the file itself. Any program running as the
same Windows user can unprotect it. On a computer joined to a domain, whoever holds the domain's DPAPI backup key can
unprotect it as well, so a domain administrator can. The entropy the app passes is a fixed public label, not a secret.
There is no item to forget, so a sign-out removes the file but not the means to open a copy of it: an older copy (a
backup, a shadow copy) still opens.

**Linux.** The store is the desktop's secret service (GNOME Keyring, KWallet's service) through libsecret: the key is
an item in the default collection, under the app's own schema, named by the handle. Any program on the user's session
bus can read the item, and looking it up can raise the keyring's unlock prompt. A sign-out, "Forget this server", the
account's deletion and unticking the switch remove the item with the file, so copies made before that no longer open;
until then they do.

**macOS, and any computer where the store is missing or refuses.** There is no key store on macOS. Nothing falls
back silently: the session is held in memory for the run and the person is asked. Only when the person chooses "a
file only your account can read" on that computer is the session written unwrapped: owner-only (`rw-------`) where the
file system has POSIX permissions, and with the permissions of the user's folder elsewhere. Anyone who can read that
file has the session. An unwrapped file is read only when the person chose it on this computer, or once as an earlier
build's file (recorded, and wrapped at the first read that can); any other unwrapped file is neither read as a session
nor deleted.

## What a browser keeps when an account ends (web client and extension)

Three kinds of record outlive the session in a browser, each for its own reason:
- **Trust records** outlive a sign-out by design (design 2026-11-15 §4.4, "a pinned card record that outlives
  sign-out and cache wipes"; spec 01 §5): the server's pin, the account's self-identity records, its account-state
  high-water marks, in the extension its item homes and personal-wrap record, and this browser's device record. (The
  web client writes no personal-wrap record, and keeps its item homes inside the offline copy, so they go with the
  copy; with the copy off it keeps them in memory only.) They are what lets the
  next sign-in tell the same server and the same account from a substituted one, so removing them at a sign-out
  would hand the next sign-in to whatever the server then serves. **A server's word that an account is gone never
  removes a pin**, nor any other trust record unless the person deleted the account from this browser: a refused refresh, a revocation and a `401` for a deleted account all
  look alike to the client, and a server able to clear a pin by saying so could then re-pin the device to a chain of
  its choosing.
- **The copy and its queue** (the web client's offline copy; the extension's sealed session snapshot) belong to the
  person: only the person's own acts delete them (T3).
- **Conveniences**: settings and a remembered address.

**Web client.**
- **Lock:** with the offline copy on, everything stays, the session's token pair included. Without it, the lock ends
  the tab's session at the server and drops the pair; the session record stays, without a pair, for the unlock card.
- **Sign-out:** the session record, its pair and the offline copy go, and nothing else does. What stays is the trust
  records (among them the pin, the self-identity records, the account-state high-water marks and sealed copy, the
  escrow fingerprint, the recovery mirror and the device record), the account's other records under its user id, its
  settings among them, and the browser's own settings.
- **A kept token** (rules of 2026-11-19, spec 03 §2 and R41 above; kept since 2026-11-19): the token of a session
  that ended with no try left is kept (`andvari.unconfirmedRefresh`, where the pair was: the tab's sessionStorage, or
  localStorage with the offline copy on), per account, four accounts at most, for the next sign-in's name. It goes at
  that account's own sign-out (in the other tabs of a per-tab browser best effort, once each has heard of it), at its
  next sign-in here and at a forgetting; another account's sign-in or sign-out leaves it. Until then it may be a live
  credential (R41).
- **"Forget this server"** (offered where the pin is forked or damaged, or where a held session has no pin): the held
  session's pair goes first, unsent,
  then the offline copy, the session record and the pin. The other trust records stay.
- **Deletion from this browser**, once the server confirmed it: nothing of the account stays. The session, every key
  scoped to the account, the self-identity records and the offline copy go, and the device record forgets the
  account's device id and address hash while keeping its secret. The pin stays (it belongs to the server, not the
  account), and so do the browser's own settings and any other account's records.
- **Refusal by the server:** with the offline copy on, the session ends and its pair goes; the copy, its queue, the
  session record, the pin and the self-identity records stay. Without it, it is the sign-out above, with no request to
  the server.
- **What names the account in plain text:** the session record (`andvari.session`) holds the address and the user id
  for as long as it exists: signed in, locked, and after a refusal with the offline copy on. The self-identity
  record's key carries the normalised address. It stays through a sign-out and "Forget this server", and goes only
  with a deletion from this browser. The device record keeps a hash of the address, not the address.
- Tests: `web/src/journeys/j6-leftbehind.journey.test.ts` pins the whole set of stored keys (localStorage,
  sessionStorage and IndexedDB) after each end above, against the real server, with the screens' own calls in their
  order; its accounts hold no shared vault and no contact, so the vault logs and the contact book are not in its sets
  (their removal at a deletion is pinned by `web/src/ui/session.account-wipe.test.ts`). Beside it:
  `web/src/ui/session-end.test.ts` (refusal by the server, and that only the person's acts delete the copy),
  `web/src/ui/session.account-wipe.test.ts` (deletion), `web/src/ui/fork-stops-traffic.test.ts` ("Forget this
  server"), `web/src/ui/signout-revoke.test.ts` and `web/src/ui/tabsession.test.ts` (sign-out and lock).

**Extension.** `extension/src/leftbehind.harness.test.ts` pins the whole set of stored keys after each end, through
the real worker, so a record added later fails it until it is decided.
- **The trust set**, kept by every end but "Forget this server": the server choice and its pin, the format marker,
  this browser's device record for the account, the account's item homes and personal-wrap record, the remembered
  address, the session-seal key, each tab's page-known facts (its own top origin and form kinds), and since
  2026-11-19 the records of which account each address is (`selfIdentityByEmail:<address>`) and of each account's
  identity key (`selfIdentityPub:<userId>`) (spec 01 §7). A mark that the extension now remembers a new account
  (`accountRemembered:<address>`, after "Forget the earlier account on this device") stays until the next sign-in
  under that address says it; "Remove data for this server" removes it.
- **Lock:** the trust set; with quick unlock on, also the quick-unlock record, its co-key and the known-logins digest;
  with it off, also the digest. The sealed snapshot goes.
- **Sign-out:** the trust set only.
- **A kept token** (rules of 2026-11-19, spec 03 §2; kept since 2026-11-19): the token of a session that ended as not
  confirmed lives in the worker's memory only, so it is never in storage and goes at a restart of the worker.
- **"Forget this server":** the remembered address, the format marker, the session-seal key and the tab facts.
- **Deletion from this browser:** none; the extension cannot delete an account.
- **Refusal by the server:** before the next lock, the trust set and the sealed snapshot, readable until that lock
  (design 2026-11-15 §4.4); the quick-unlock record and the digest go at the refusal. After the lock, the trust set only.
- **What names the account in plain text:** the device record's key carries the address, until "Forget this server";
  the remembered address (A15 (c)) carries it in its value and stays even then.

**The extension's test build** (rules of 2026-11-19; kept since 2026-11-19, for Chrome, Edge and
Firefox, minified and with no source maps, and refused beside the builds for Safari, for debugging,
for the interface tests and for card filling). One setting of the build makes it, and no other setting
goes beside it; such a build says "andvari dev" and the commit it was built from in its manifest,
popup and options page; the test server takes the live server's place as the server it starts at
and as its only granted host, with no card of that server built in, so that server is taken
through the Trust Gate like any other server of the person's own; it has no update address and no
update channel, and a Firefox id of its own. The build removes its output and fails where a test
build names the live server anywhere, or where any other build names the test server; every other
build is byte for byte what it was without the setting; and the script that packages the extension
for the stores refuses to run with that setting. In such a build the first screen's button for the
public server is refused, and the test server is reached as "Your own server". So a test build
cannot be mistaken for the released extension, cannot reach the live server, and cannot be sent
to a store.

## Autofill (client-side, Android)

The autofill service honors a fill request's web domain only from a browser it verifies by
**signing certificate** (package name alone is spoofable — an app can install under an
absent browser's package id). A package that is not pinned, not installed, or whose cert
does not match its pin **fails closed**: no web-domain trust → only `androidapp://<pkg>`
URIs match it, never web items — and never for a KNOWN browser package (2026-10 security
review): a browser shows every web origin, so `androidapp://<browser>` matches nothing, and an
untrusted known browser gets no login fill at all. Residual: a browser whose release cert we have not pinned
won't offer autofill until its digest is added (safe, functionality-only). The match rule
(2026-07-10 amendment — spec 02 §3.1, `docs/design/2026-07-10-etld1-psl-matching.md`) is
registrable-domain (eTLD+1) equality against the vendored PSL snapshot (explicit rules
only): sibling subdomains of the same registrable domain fill each other, bare-public-suffix
and cross-registrable fills are refused, and hosts the snapshot cannot positively resolve
(`.lan`/`.local`/unknown TLDs) degrade fail-safe to the pre-amendment label-boundary suffix
rule. Digital Asset Links verification is the P6 loosening. The service never reads field
values and never logs field content, item names, or full URIs; local fill diagnostics
persist host-only frame domains + the calling package in app-private storage (last-event
summary always; a ring buffer only while the 24 h debug toggle is armed, purged on disarm).

**2026-11 review of the Android app.** One platform fact decides the rules below: whatever an authentication activity
returns travels through the requesting app's own process. That app can read every value in the result without the
person picking a row, and it can keep the row's IntentSender and send it again. A dataset the service answers
directly stays with the system until the person picks it. "Verified browser" means a browser whose signing
certificate is pinned, or one approved on this device under (d).

(a) **No value rides an authentication result unless the requesting app is entitled to all of it, and nothing that
names an item rides a result that passes through an app that is not a verified browser.** Such a result carries no
value, no card's name, not how many there are, no login's name and never a user name: at most one generic row for
logins and one for cards, in the same words whatever the vault holds. Its tap opens andvari's own chooser, where the
items are listed and the choosing happens: a vetted app's own login (the app-fill gate's silent verdict, A14 (i))
fills on the pick; any other login, and every card, shows its confirm in that window, which returns that one item.
With one generic row there is one way in: the app holds no sender that raises a confirm for an item of its choosing. A
verified browser's result keeps one row per item; a known browser that is not verified gets no row in a result. The
service's direct response, which stays with the system until the person picks a row, still lists one row per item.
The confirmation, trust, chooser and unlock windows are opaque and cover the screen: nothing of the requesting app
shows around them. On Android 10 and 11, where other apps' overlays cannot be hidden, a touch that arrives while the
window is obscured, wholly or partly, is dropped. Once the unlock's IntentSender has delivered a result, a later use of
the same sender shows nothing and returns nothing; a prompt the person cancelled may be tried again.

(b) **A payment card goes to an app only through a confirm that names the app, every time.** This replaces "card
datasets are not app-gated" in A14 (i). In a verified browser the wallet posture stands: a card is not bound to an
address, and one pick in the list fills it. In every other app a card row carries no values: its tap opens a confirm
that names the app (label, package, installer and signer, as the app-fill confirm shows them) and the card (its name,
brand and last four digits), with the app-fill confirm's defences (other apps' overlays hidden, touches through
another window dropped, the button armed after a delay), and returns that one card. An app is never remembered for
cards. Everywhere, card rows are offered only when the field in focus is itself a card field. Residual: the tap is the
person's. A phishing checkout in a verified browser, or an app the person confirms, still receives the card.

(c) **An app's login does not fill another site's page inside that app, and a page inside an app saves nothing.** In
an app that is not a verified browser, an `androidapp://` login fills a field that reports a web domain directly only
when that domain also matches one of the same login's own web addresses. The app's claim can only narrow what the
package match gives, never widen it. On any other page the login is offered only through the app-fill confirm, which
names the page, is shown every time and is never remembered. An HTML field that reports no web domain is a page of
unknown address: it is never filled directly and never matched to the app's own login, through a confirm or
otherwise. When the captured fields belong to a web page (a field carries a web domain, or is an HTML field), andvari
offers no save: nothing is queued and nothing is replaced. Residual: the page confirm's tap is the person's, and a page
the person confirms receives the login; a login that holds only the app's address meets that confirm every time on a
sign-in screen the app draws as a web page, and a login typed there is not saved.

(d) **Trusting a browser on the device** shows the package, the installer and the signer, with the same three
defences as the app-fill confirm. It is refused for an id whose certificate is pinned: a mismatch there is a warning
and no fill. A browser is trusted by its current signer (the last certificate of its signing history, or every signer
of an app signed by several at once), for a pin and an approval alike. The approval is stored with the signer it was
given to, and it does not cover another signer that only appears in the signing history: after a browser's key
rotation the person is asked again, with the changed-signer warning, and an APK signed with the retired key alone is
not trusted. Settings lists trusted browsers and remembered apps, each with a revoke.

(e) **A plain-http frame** matches only an address saved as `http`, as the page rule in core does. Residual: a frame
for which the browser reports no scheme is matched as before. Browsers that run in the platform's compatibility mode
report one domain for the whole page, so a third-party frame on a sign-in page is filled with the page's login.

## Non-goals
Nation-state adversaries; side-channel resistance beyond libsodium's own; protection
of an unlocked session from its own OS; multi-org tenancy; plausible deniability.
