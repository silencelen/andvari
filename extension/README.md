# andvari browser extension (spike)

**Status: feasibility spike, not built.** Full go/no-go analysis, architecture, and the crypto-in-MV3
blocker + resolution are in [`docs/design/2026-07-08-browser-extension-spike.md`](../docs/design/2026-07-08-browser-extension-spike.md).
Verdict: **GO**.

`manifest.json` here is the concrete starting point — it encodes the resolved unknowns:
- `host_permissions` for the tailnet server origin → cross-origin `fetch` without CORS.
- `content_security_policy.extension_pages` with `'wasm-unsafe-eval'` → WASM allowed (but NOT JS
  `eval`, which the web's libsodium glue uses — see the spike doc's Unknown 1 for the @noble /
  sandbox resolution).
- MV3 service worker + content script + popup split.

## Next concrete step (de-risks the one real blocker)

A Node/vitest PoC that runs `@noble` Argon2id + XChaCha20-Poly1305 against the existing
`web/src/crypto/*.test.ts` vectors and asserts byte-identical output. If it matches, the extension
uses pure-JS crypto (no WASM, no sandbox, identical in Chromium + Firefox). Only then wire the
`background.js` / `content.js` / `popup.html` referenced by the manifest.

## Verify (owner/dev, on a real browser)

See the spike doc's "What must be verified on a real browser" — load unpacked, confirm no CSP
violation, a crypto round-trip, and a `fetch` to `/api/v1/client-policy`.
