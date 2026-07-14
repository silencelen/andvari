# Signed update channel (H2) — design

**Date:** 2026-07-13 · **Status:** ratified (owner chose Option B — workstation key) · build-ready pending owner keygen
**Source:** pentest 2026-07-13 finding **H2** (`docs/pentest/2026-07-13-comprehensive-pentest.md`).

## §0 Threat & goal

The desktop `checkForUpdate` (`app-desktop/.../desktop/Platform.kt:64`) fetches `{base}/downloads/manifest.json`, parses a per-OS `PlatformBuild{version,url,sha256}`, and **discards the `sha256`** — it only compares the version and shows a banner pointing at the download. The extension does the same via `background.ts` → `isNewerVersion` (`version.ts`). Both read the manifest from **CT122**, and the installers are unsigned. So a **T1 server compromise** (the model's primary in-scope adversary, otherwise bounded to "ciphertext only") can bump the manifest version + drop a trojaned `.deb`/`.msi`/extension zip, and the *trusted in-app banner* leads the user to install it → **client RCE + master-password capture**.

**Goal:** a client must refuse any update whose provenance it cannot cryptographically verify against a key the server does not hold — turning a hostile manifest/installer into a no-op, not RCE.

## §A Key custody — Option B (owner workstation)

The signing **private key MUST NOT live on CT122** (or a server compromise re-signs trojans, voiding the scheme). Owner chose **Option B**: the private key lives on the **owner's dev workstation** (the same anchor that already pushes releases). Releases are signed there. huginn (which builds artifacts) never sees the private key; it produces the *unsigned* manifest + installer shas, the owner signs on the workstation, and the signed manifest is what lands in `/downloads`.

- Rejected **A (offline/air-gapped)**: max security but a manual per-release offline step — overkill for household cadence.
- The **public key** is a compile-time constant in every client (see §E). The server cannot change it.

## §B Signing scheme

- **Algorithm:** Ed25519 detached signature via libsodium `crypto_sign_detached` / `crypto_sign_verify_detached` (already available in `core` + web/extension noble; no new dep). 64-byte sig, 32-byte pubkey.
- **What is signed:** the **canonical bytes of the manifest with the `sig` field removed** — i.e. the update payload the client will act on. Canonicalization must be deterministic and identical on the signer and every verifier (see §C).
- **Anti-rollback:** the signed manifest carries a monotonic `seq` (integer, strictly increasing per release) alongside `version`; a client refuses a manifest whose `seq` is **≤ the highest `seq` it has ever accepted** (persisted locally). This blocks a T1 server replaying an *old validly-signed* manifest to force a downgrade to a known-vulnerable build. (Version alone is insufficient — a valid old manifest is validly signed.)

## §C Manifest format change

Add a top-level signature envelope. Current `/downloads/manifest.json`:
```json
{ "linux": {"version","url","sha256"}, "browserExtension": {"version","chromeUrl","firefoxUrl"}, "windows": {"version","url","sha256"} }
```
New (additive; old clients ignore unknown fields, see §H):
```json
{
  "seq": 42,
  "signedAt": "2026-07-13T…Z",
  "linux": {"version","url","sha256"},
  "browserExtension": {"version","chromeUrl","firefoxUrl","chromeSha256","firefoxSha256"},
  "windows": {"version","url","sha256"},
  "sig": "<base64 Ed25519 detached sig over the canonical payload>"
}
```
- **`chromeSha256`/`firefoxSha256` added** to `browserExtension` — today the extension entry carries no hash, so the signed manifest must commit to the zip digests too (else a T1 server swaps a signed-manifest-referenced zip).
- **Canonical payload = the object with `sig` removed, serialized by a fixed canonicalizer.** Chosen canonicalizer: **sorted-keys, no-whitespace JSON (RFC 8785-lite: sort object keys, `,`/`:` separators, UTF-8, numbers as minimal integers).** A single shared implementation in `core` drives the signer; the desktop verifier reuses it; web/extension use a byte-identical JS port (pinned by a shared test vector — the cross-impl vector discipline the repo already uses for crypto).
  - *Simpler alternative if canonicalization proves fragile:* sign a **detached `manifest.json.sig`** over the **exact bytes of a separate `manifest.signed.json`** that the client fetches verbatim (no re-canonicalization) — the signer emits both, the client verifies the sig over the raw fetched bytes, then parses. This sidesteps canonical-JSON entirely. **Breaker to decide** between canonical-in-place vs. raw-bytes-detached; the raw-bytes form is more robust and is the recommended default.

## §D Client verification flow (fail-closed)

Desktop `checkForUpdate` and extension `checkForUpdate` change from "compare version" to:
1. Fetch the manifest (raw bytes if using the detached-`.sig` form).
2. **Verify the Ed25519 sig against the pinned pubkey.** Fail → **no update offered**, surface a *distinct* "couldn't verify the update's authenticity — not offering it" state (never a silent skip, never a normal update banner). This is the crux: an unsigned/forged manifest is inert.
3. Check `seq > lastAcceptedSeq` (persisted) and `version` newer than this build. Else → no offer.
4. On the user choosing to update: download the installer, **verify its sha256 against the signed manifest** before running/handing it to the user. Mismatch → refuse + warn.
5. Persist `lastAcceptedSeq` only after a fully-verified manifest.
- **Refuse `http://` base URLs / require HTTPS** for the update fetch (an on-path attacker on a LAN base URL otherwise MITMs the pre-verification fetch; the sig defends content, HTTPS defends the fetch + the 426 side-channel).

## §E Pinned public key

- A 32-byte Ed25519 pubkey as a compile-time constant: `core` `UpdateKey.PUBLIC` (base64) consumed by desktop; a JS mirror in web/extension. Baked, not fetched — the server can never supply it.
- **The owner provides the pubkey** (from §F). Until then the build uses a clearly-marked **test pubkey** and the feature is **inert on real releases** (a manifest signed by the test key won't verify against a real pinned key, so the safe default is "no update offered" — which is strictly safer than today, just not yet usable). Swapping in the real pubkey is a one-line change + a client rebuild/re-release.

## §F Keygen ceremony (owner, on the workstation)

1. On the workstation (NOT huginn/CT122), mint an Ed25519 keypair (the signer tool's `keygen`, or `age-keygen`-style). Private key → the workstation's secret store (e.g. `~/.andvari/update-signing.key`, 600); **never** leaves the workstation.
2. Owner sends huginn/me the **public key only** (32 bytes base64). I bake it into `UpdateKey.PUBLIC` (+ JS mirror), rebuild the clients, re-release.
3. Record the pubkey fingerprint in `docs/runbooks/` next to the escrow/recovery ceremony record; a lost private key = mint a new one + re-pin + re-release (no data at risk — it only signs updates).

## §G Signer tool

A small offline CLI in `tools/` (pattern: `recovery-cli` — no network on the classpath): `andvari-sign-updates`:
- `keygen` → prints the keypair (private to a 600 file, public to stdout).
- `sign <manifest.json> --key <privkey>` → validates the manifest, injects `seq`/`signedAt`, computes the canonical/raw payload, signs it, emits the signed manifest (or `manifest.signed.json` + `.sig`). Runs on the owner's workstation.
- Release flow: huginn builds artifacts + emits an *unsigned* manifest with the installer shas → owner runs `sign` on the workstation → the **signed** manifest is what `deploy`/`/downloads`-publish uploads.

## §H Rollout (no client breakage)

- The `sig`/`seq`/`chromeSha256` fields are **additive**; today's fielded clients (which don't verify) ignore them — no break.
- New (verifying) clients: introduce verification as **required from day one for THOSE clients** — a verifying client simply won't offer an update it can't verify. Because updates are **nag-only** (no auto-install), the worst case for a verifying client pointed at an as-yet-unsigned manifest is "no update banner" — safe, non-disruptive.
- Once the real pubkey is pinned and releases are signed, every new client verifies; old clients keep working (they just never gained the protection — acceptable, they update forward into a verifying build).

## §I Installer OS-signing (defense-in-depth, follow-on)

- **MSI:** Authenticode sign (owner's Windows box; `signtool` with a cert). 
- **deb:** GPG-sign (`dpkg-sig` / a detached `.asc`).
- These protect a *hand-downloaded* installer (outside the in-app flow) and are independent of the manifest sig. Follow-on cut; not required for the core H2 fix.

## §J APK / devstore note

The APK updates via **devstore (VM115 sindri)** — a **separate trust domain from CT122**, and Android already enforces same-signer for APK updates (a differently-signed trojan APK is rejected on update). So the APK is lower-priority for the CT122-T1 threat. The same manifest-signing pattern applies to `dist/latest.json` if we want to harden the devstore path too (optional follow-on).

## §K Build plan & tests

Cut order (each: build → test): 
1. `core` `UpdateManifest` model + canonical/raw payload + `UpdateKey.PUBLIC` (test key) + verify fn + a **shared test vector** (a fixed manifest + test-key sig, byte-pinned across Kotlin + JS).
2. Signer tool (`tools/update-signer`) with `keygen`/`sign` + tests (round-trip: sign → verify; tamper → reject; rollback `seq` → reject).
3. Desktop `Platform.kt` verify flow (sig + seq + installer sha) + fail-closed UI copy.
4. Extension `background.ts` verify flow + `chromeSha256`/`firefoxSha256` + fail-closed.
5. (owner) keygen ceremony → pin real pubkey → rebuild/re-release. (follow-on) MSI/deb OS-signing.

**Verification:** cross-impl sig vector green in `verify.sh`; a scripted end-to-end (sign a manifest with the test key → desktop/ext verify accepts; flip a byte → rejects; replay an older `seq` → rejects; swap an installer sha → rejects).

## §M — Breaker review (2026-07-13): REVISED plan (authoritative; supersedes §D/§E/§I above where they conflict)

The breaker returned **GO-WITH-CHANGES** with one verdict-changing finding. **§M is the build contract.**

**D1 (CRITICAL — reshapes the fix). The manifest signature does NOT close the H2 RCE by itself.** The desktop + extension are **nag-only**: `checkForUpdate` returns a *version string* and the UI opens the **browser** at `{base}/downloads` (`Ui.kt:79,91-100`; `DesktopState.kt:157,344`); grep confirms **no in-app installer download** exists (only vault-attachment fetches). The extension likewise stores `updateInfo{chromeUrl,firefoxUrl}` and shows links (`background.ts:386-398`); the browser never auto-applies a sideloaded zip. So the `sha256`/`chromeSha256`/`firefoxSha256` fields are **verified by nobody** (§D#4 is unreachable dead code). A T1 server that serves a *genuinely-signed* manifest (or just knows the real version) still lands the user on the **T1-controlled** `/downloads` page → trojaned installer → RCE. **The signature only stops a *fabricated* nag.**
→ **The load-bearing control is OS/store-level installer signing, ELEVATED from §I "follow-on" to REQUIRED:**
- **MSI → Authenticode-signed** (owner: a code-signing cert + the Windows box). Windows/SmartScreen then rejects a trojan signed by anyone else.
- **deb → GPG-signed** (owner: a GPG key; `dpkg-sig`/detached `.asc`) so the user/apt can verify.
- **Extension → publish to the Chrome Web Store + Firefox AMO** (store signing is the only real integrity for a browser extension; self-hosted zips have none). If store-publishing is undesired, the extension H2 residual is **accepted** (documented).
- The manifest-sig (below) becomes a **secondary** control: it kills the fabricated in-app nag + downgrade-steering, but is not the primary RCE defense.

**D3 (HIGH). Test-key interim build is forgeable + falsely "verified."** Pinning the *test* pubkey means a test-key-signed manifest verifies, and the test seed lives in the dev tree (`vector-gen`) → forgeable, with a "authenticity verified" banner. → Clients **hard-disable all update offers at compile time when `UpdateKey.PUBLIC == TEST_KEY`** (constant compare, fail-closed regardless of any sig). "Inert" = no update path executes, not "verifies against a test key." No client ships to real users until the real pubkey is pinned.

**D2 (HIGH). Crypto is NOT "already available."** `CryptoProvider` has no `crypto_sign` (`CryptoProvider.kt:19-57`; Ed25519 grants were deferred to P6, `LifecycleProof.kt:13`). → core: extend the `expect`/`actual` interface with `signVerifyDetached` (jvm+android lazysodium `crypto_sign_verify_detached`). Extension: use the **already-present `tweetnacl` `nacl.sign.detached.verify`** (NOT noble — not a declared dep). web: libsodium `crypto_sign_verify_detached`.

**D6 (MEDIUM). Raw-bytes-detached `.sig` confirmed (canonical-JSON cross-impl is a footgun), BUT clients must verify the EXACT fetched bytes.** Today desktop uses `BodyHandlers.ofString()` (`Platform.kt:67`) and the extension `await resp.json()` (`background.ts:392`) — both discard/round-trip the bytes. → desktop `ofByteArray()`; extension `await resp.arrayBuffer()`; verify raw bytes BEFORE parse; fetch `manifest.json.sig` as a second request; either fetch failing → fail-closed.

**D4 (MEDIUM-HIGH). `seq` is partly redundant + doesn't cover fresh installs.** The version gate already blocks strict downgrade of an existing install (`Platform.kt:72`, `version.ts:12`). `seq`'s real value is only blocking rollback of a client that already accepted a higher seq. A **fresh install (floor 0)** can still be steered to any validly-signed *older-but-genuine* (known-vuln) version > its build. → (a) bake a compile-time `MIN_SEQ` floor to shrink the fresh window; (b) actually **consume `signedAt`** — after N days without a fresh signed manifest, surface a quiet "update channel may be stale" state (withholding a security update by serving stale-but-signed / strip-sig is irreducible; make it *detectable*).

**D5 (MEDIUM). Fail-closed state must be QUIET.** T1 can strip the sig on every fetch to force a permanent scary "couldn't verify" banner → DoS + cry-wolf training. → keep it a quiet, non-modal, distinct-from-"up to date" state; never a modal nag for an unreachable/tampering server.

**D7 (MEDIUM). Key rotation bricks the fleet; two hand-mirrored keys drift.** A single pinned key, if lost (Option B laptop dies), rejects all future manifests forever (fail-closed brick). → pin a **key SET** (accept any of N pinned keys) for overlapping rotation; single-source the pubkey bytes (generate the JS mirror from the Kotlin constant) + pin via the shared vector.

**D8 (LOW-MED). `seq` source.** A workstation counter file can be lost/reset → self-inflicted denial-of-update. → derive seq as `max(currently-published manifest seq)+1` (read the live manifest, ensure strictly greater; guard NTP backsteps) — stateless, self-correcting.

**D9 (LOW). Drop hard HTTPS-only.** It breaks the documented LAN-dev path (`http://192.168.2.122:8080`, `DesktopSession.kt:126` + `network_security_config.xml`) and is redundant once signed (an on-path LAN attacker can only DoS the fetch → fail-closed, which they can do anyway). → drop it, or scope to allow the RFC1918/loopback dev hosts already allow-listed, and don't emit the scary warning for a known-dev http base.

**D10 (context). The web `/downloads` hub can never be a verifier** — CT122 re-serves the bundle every load, so T1 rewrites any web-JS check. Only the *installed* desktop binary + *installed*/store extension are valid verifiers.

### Revised control stack (what actually closes H2)
1. **LOAD-BEARING — installer integrity the OS/store enforces:** Authenticode MSI + GPG deb + store-published extension. Independent of CT122; protects the bytes the user runs.
2. **SECONDARY — signed manifest + pinned key-set + seq/`signedAt` + fail-closed-quiet:** kills the fabricated nag + downgrade-steering + makes withholding detectable. Buildable by me (with D2/D3/D6 fixes) using a test key until the owner pins the real one.

### Owner decisions this surfaces (H2 is more owner-gated than it first looked)
- **MSI code-signing cert** (for Authenticode) — buy/provision + sign on the Windows box.
- **GPG key** for the deb (owner-held).
- **Extension:** publish to Chrome Web Store + AMO (real signing), or accept the sideload residual.
- **Manifest-sig keypair:** mint Ed25519 on the workstation, send me the pubkey (§F) — the one piece I can wire immediately.

## §L Open questions for the breaker (RESOLVED — see §M)

1. Canonical-JSON-in-place vs. raw-bytes-detached-`.sig` (§C) — recommend raw-bytes; confirm.
2. `seq` source of truth + how the signer increments it monotonically (a counter file on the workstation? derive from a UTC timestamp?).
3. Extension self-update reality: the extension is **sideloaded** (unpacked/zip), so the browser won't auto-apply an update — the "update" is a user action. Confirm the verify gate belongs on the *nag* (don't tell the user to update to an unverifiable build) and that there's no auto-apply path to also gate.
4. Does refusing `http://` base URLs break the documented LAN-cleartext dev path (`.2.122`)? If so, scope the HTTPS-only requirement to the update fetch only, or allow the LAN IP explicitly.
