# Spike — andvari browser extension (PC autofill)

**Status:** go/no-go feasibility spike (owner-requested 2026-07-07). **Verdict: GO**, with one real
blocker that has a clean resolution (crypto-in-MV3). Chromium (MV3) first; Firefox (MV3) second.
This doc resolves the four unknowns, recommends an architecture, and lists what must be verified on
a real browser (I can't load an unpacked extension in this environment — same class of owner-step as
the Fold autofill / Windows MSI).

## Goal

PC users get the same "andvari knows this site → fill" and "new login → save" that Android now has,
in the browser — reusing the web client's already-built, vector-tested pieces (`UriMatch`, the crypto
envelope, the API client) rather than a second implementation.

## Architecture (MV3)

```
┌─ content script ─────────────┐     ┌─ background service worker ──────┐
│ detects login forms (DOM)    │────▶│ session (unlocked VK, in memory) │
│ reuses UriMatch host logic   │◀────│ AndvariApi over host_permissions │
│ renders fill/save affordance │ msg │ decrypt items / encrypt on save  │
└──────────────────────────────┘     └──────────────────────────────────┘
        ▲                                     ▲
        │ user gesture                        │ master password (once/session)
   ┌─ popup (unlock + vault list) ────────────┘
```

- **Content script** — DOM form detection (a browser-native classifier, NOT the Android
  `AssistStructure` one; see Unknown 4). Reuses `web/src/vault/urimatch.ts` host-matching verbatim
  (it's pure + vector-tested). Requests fills / offers save via messages to the worker; never holds
  the VK or plaintext beyond the field it fills.
- **Background service worker** — the only holder of the unlocked session (VK) and the `AndvariApi`.
  Decrypts matched items on demand; encrypts a new/edited item on save. Uses the SAME wire/crypto as
  the web app, so it's the same zero-knowledge posture (server sees only ciphertext).
- **Popup** — master-password unlock, vault/item list, settings. Reuses the web account-unlock path.

## The four unknowns — resolved

### 1. libsodium-WASM under the MV3 service-worker CSP — **the real blocker, resolvable**

MV3 lets `content_security_policy.extension_pages` add `'wasm-unsafe-eval'`, which permits
`WebAssembly.compile/instantiate`. **But that does NOT permit JS `eval` / `new Function`, and the
web client's `libsodium-wrappers-sumo` (emscripten glue) uses them** — so libsodium as-is will throw
in an MV3 service worker. This is the classic libsodium-in-MV3 wall, and it's the one thing that
makes this a spike rather than a copy-paste.

Two clean resolutions (recommend B):

- **A — sandboxed/offscreen crypto.** Run libsodium in a `sandbox` page (Chromium: an offscreen
  document; Firefox: a sandboxed iframe) whose CSP allows `'unsafe-eval'`, and message it from the
  worker. **Pro:** reuses the exact, proven web crypto — zero reimplementation risk. **Con:**
  message-passing plumbing + an offscreen-document lifecycle that differs across Chromium/Firefox,
  and the VK transits an internal postMessage boundary.
- **B — pure-JS crypto (recommended).** Replace libsodium with `@noble/*` (no WASM, no `eval` → MV3-
  and cross-browser-clean) **for the extension's reduced surface only**: `crypto_pwhash` → Argon2id
  (`@noble/hashes/argon2`), `crypto_aead_xchacha20poly1305_ietf` → `@noble/ciphers/chacha`
  (`xchacha20poly1305`), plus blake2b/HKDF (`@noble/hashes`) and X25519 (`@noble/curves`) if shared
  vaults are in scope. **Pro:** no sandbox, identical in Chromium + Firefox, and — crucially — the
  existing crypto **test vectors are the correctness gate**: a @noble envelope that matches
  `web/src/crypto/*.test.ts` output is provably interoperable with every other client. **Con:** a
  crypto reimplementation (medium, security-sensitive — but vector-pinned and small).

The extension does NOT need the full crypto set. It needs unlock (Argon2id + key derivation) and item
AEAD (XChaCha20-Poly1305). **Escrow (sealed box) and attachments (secretstream) are out of v1** —
they're not part of fill/save — which shrinks the @noble surface to a very tractable core.

**PoC RESULT (2026-07-08) — path B is DE-RISKED.** `web/src/crypto/noble-extension-poc.test.ts` runs
`@noble` against libsodium and the shared `spec/test-vectors/kdf.json`, all green:
- **Argon2id** (ops→t, memBytes→m KiB, p=1, version 0x13) == kdf.json == libsodium `crypto_pwhash`.
- **HKDF-SHA256** == kdf.json.
- **XChaCha20-Poly1305** byte-identical to libsodium's `crypto_aead_xchacha20poly1305_ietf`, and
  interops **both directions** (each opens the other's ciphertext).
- **Full item envelope** (`version‖alg‖nonce‖ct`) byte-identical to the core `Envelope`.

So @noble is wire-interoperable with web/Android/desktop at zero cost — **path B GO for correctness.**

**The one caveat the PoC surfaced — unlock latency.** Pure-JS Argon2id at the account's production
params (ops=3, **64 MiB**) is **~5.8 s** for a single unlock (vs libsodium-WASM's sub-second). It's
per-unlock, not per-fill (the SW caches the VK; the frequent AEAD path is instant), and the params
are fixed by the account (can't be lowered without breaking key derivation). Resolutions:
1. **Ship B with a worker + spinner** (simplest): run the KDF in a Web Worker so the popup doesn't
   freeze, show "Unlocking…". A ~5 s one-time unlock is tolerable but not great.
2. **Hybrid** (if unlock must be snappy): @noble for everything EXCEPT the unlock KDF, and run only
   Argon2id in a sandboxed/offscreen page (path A) for that single call — fast unlock, no sandbox on
   the hot fill path.

Recommendation: **B + worker for v1**; revisit the hybrid only if testers find unlock too slow.

### 2. host_permissions vs CORS — **solved, not a blocker**

`host_permissions: ["https://andvari.taila2dff2.ts.net/*"]` lets the extension `fetch` that origin
cross-origin **without CORS** (extensions with host permissions are exempt). The server needs no CORS
header for the extension, and the tailnet-only origin stays private (the extension only works when the
machine is on Tailscale — same as the web app). Bearer-token auth reuses the web `AndvariApi` as-is.

### 3. Service-worker session lifecycle — **design, not a blocker**

MV3 service workers are killed aggressively, and the unlocked VK must NOT be persisted to disk (ZK).
Contract: keep the VK in worker memory only; on worker death it's gone and the user re-unlocks from
the popup (accepted UX, mirrors the app's auto-lock). Use `chrome.alarms` + the org auto-lock policy
to lock proactively; never write the VK to `chrome.storage`. The durable *ciphertext* cache (for
offline/fast list) MAY live in IndexedDB exactly as the web client's cache does — same policy gate.

### 4. Form detection + reuse — **partial reuse**

`UriMatch` (host↔saved-URI) reuses verbatim. The Android `FieldClassifier` does NOT — it reads an
`AssistStructure`; the browser reads the **DOM** (`input[type=password]`, `autocomplete=` tokens,
`name`/`id` keywords, label proximity). So the extension gets a small browser-native classifier that
applies the SAME rule *ideas* (the keyword/hint sets can be shared as data), plus DOM-only signals
the app can't see. This is additive work, low risk, and standard for a web extension.

## Verdict

**GO.** Nothing is a hard wall. The only non-trivial risk — crypto under MV3 — has a recommended
resolution (pure-JS @noble on a reduced surface, vector-gated) and a proven fallback (sandboxed
libsodium). CORS is a non-issue, session lifecycle is a known pattern, and the highest-value web
pieces (UriMatch, the API client, the wire format) reuse directly.

## What must be verified on a real browser (owner/dev step)

I scaffolded `extension/` (manifest + worker + content + popup starting points) but cannot
`load unpacked` here. On a real Chromium:

1. Load `extension/` unpacked → the worker registers, no CSP violation in the console.
2. **The crypto smoke test** (the go/no-go proof): the worker inits its crypto (@noble PoC or the
   sandbox) and round-trips one XChaCha20-Poly1305 encrypt/decrypt — no `eval`/CSP error.
3. A `fetch` to `https://andvari.taila2dff2.ts.net/api/v1/client-policy` succeeds (host_permissions,
   no CORS error).
4. The content script logs detected login fields on a real login page.
Then the same on Firefox (MV3) — mainly to confirm the sandbox/offscreen difference if path A is used.

## Scope cuts for the spike / v1

Escrow + attachments crypto (not needed for fill/save), inline-in-page UI polish, and shared-vault
acceptance (needs X25519 — add if wanted). The spike proves the spine: detect → match → decrypt/fill,
and capture → encrypt → save.
