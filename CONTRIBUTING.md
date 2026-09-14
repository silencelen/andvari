# Contributing

andvari is a small, solo-maintained project. Pull requests are welcome but may sit for a while,
and a change that alters the wire format, the key hierarchy, or a crypto construction needs a spec
change first — see below. If you are here to *check* the code rather than change it, the first
section is the one you want.

## Verify it yourself

The pitch is "don't trust us, read it", so the verification path is meant to be short.

```sh
git clone https://github.com/silencelen/andvari
cd andvari
(cd web && npm ci --ignore-scripts)
(cd extension && npm ci --ignore-scripts)
bash scripts/verify.sh
```

`npm ci` installs exactly the committed lockfile; `--ignore-scripts` refuses to run any
dependency's install hooks (both `.npmrc` files set it too, so a plain `npm install` behaves the
same — the flag is spelled out so the property survives a copy-paste into another checkout).
Nothing in either tree needs a hook: esbuild's postinstall only swaps in the platform binary that
its optional `@esbuild/<platform>` package already provides. A password manager's build host is
the last place a transitive package should get to run code at install time.

You need **JDK 17**, **Node ≥ 22**, and — because `verify.sh` includes the Android client — an
**Android SDK**, found via `ANDROID_HOME` or an `sdk.dir` line in `local.properties`. Without one,
run the suites individually and skip the `:app-android` line; everything else stands alone.

**What runs when you open a PR, and what does not** (the full record is docs/ROADMAP.md's
"CI posture" section). `.github/workflows/verify-js.yml` runs the two JS/TS suites plus both
typecheck legs — web and extension — on every pull request. **The Kotlin half of the gate is not
run in CI at all**: `:core`, `:server`, `:app-desktop`, `:app-android` and `tools/` want ~8-12 GB
and do not fit a GitHub-hosted runner. So a green check on a PR touching `core/`, `server/`,
`app-*/` or `tools/` proves the JS half only; such a PR still needs a local `scripts/verify.sh`
before merge, and nothing enforces that but the release gate.

`scripts/verify.sh` is the gate every release goes through. In order, it:

1. **Release-version consistency** — core, Android, desktop, and web must all report the same
   client version, and the top `CHANGELOG.md` heading must name it. One skew fails the gate.
   The two `package-lock.json` roots are held to the same rule: npm writes that number from
   `package.json` and nothing at install time ever reads it back, so a bump that edits only
   `package.json` leaves the lock silently stale (it sat three fleet versions behind once). After
   a version bump, refresh each lock **without** touching the resolved dependency tree:
   `(cd web && npm install --include=dev --package-lock-only)` and the same in `extension/`.
2. **Endpoint-agnostic docs** — no reference-instance address and no private host name in the
   current-facing prose, the prose half of the rule the clients are pinned to
   (`docs/design/2026-07-15-multi-tenant-endpoints.md` §5.5). The scanner is
   `scripts/ci/doc-leak-scan.sh`: it reads `spec/`, `docs/` and the root/module prose, and it
   matches address *classes* (RFC1918, CGNAT/tailnet) and machine names, not a list of strings
   that already leaked. Dated records — `docs/design/`, `docs/hardening/`, `docs/compliance/`,
   the closed campaign plans, and the two runbooks whose subject *is* a named machine — are
   exempt, each for a reason stated in the script: they are history, not instructions. Its own
   fixtures (`scripts/ci/fixtures/doc-leak/`) are checked by the gate too, so a pattern that
   stops firing fails here.
3. **Kotlin** — `:core`, `:server`, `:app-desktop` and every `tools/` CLI (`recovery-cli`,
   `backup-cli`, `update-signer`, plus a compile of `vector-gen`): RFC pins for the primitives, the
   shared vectors, and full server integration.
4. **Android** — unit tests plus a compile gate over the app and its autofill service.
5. **TypeScript (web)** — `vitest` plus `tsc --noEmit`. This suite also carries the extension's
   cross-engine pins (see below).
6. **Extension** — `tsc --noEmit` plus its `node --test` suites, with a floor on both the number of
   suite files and the number of tests the runner reports back. `node --test` exits 0 when its glob
   matches nothing, so "the runner found the suite" has to be asserted separately from "the suite
   passed".

`scripts/e2e.sh` goes further: it starts a real server, drives it with real client code over a real
WebSocket, and `SIGKILL`s it mid-flight to prove crash-durable idempotency.

## What the vectors prove

There are two independent implementations of the same spec — Kotlin in `core/`, TypeScript in
`web/src/crypto` and `extension/src/crypto.ts`. They are not allowed to check each other; each is
checked against the frozen JSON fixtures in `spec/test-vectors/`, which pin exact bytes for the
KDF, the AEAD envelope and its associated-data constructions, wrapping, sealing, shared-vault
grants, export, TOTP, URI matching, and more. A change that alters a byte breaks both suites, in
two languages, before it can ship.

Most of those files are generated from the Kotlin reference implementation by `tools/vector-gen`;
the rest are hand-authored fixtures. `spec/test-vectors/README.md` is the provenance manifest —
which file is which, and the counts — so it is not repeated here. Both engines consume all of
them either way.

Some safety-critical extension values are pinned from the **web** suite, in
`web/src/extension-pins.test.ts`, because the extension has no cross-engine harness of its own.
That file says so at the top; if you change a pinned constant, that test is designed to break
first, deliberately.

## Working on the code

- **`spec/` is normative.** Code follows the spec, never the reverse. If your change alters
  protocol or crypto behaviour, change `spec/` (and its vectors) in the same PR and say why.
- **One hard invariant**: a server can make a client safer, never laxer (`spec/03` §1.1). A change
  that lets a server relax a client-side control is a bug, however convenient.
- Run `bash scripts/verify.sh` before you open the PR, and say in the description what you ran.
- Behaviour changes need a test. Match the surrounding style — this codebase comments *why*, at
  length, especially around anything security-relevant.
- Gradle is tuned for a small build host; serialize concurrent invocations with
  `flock /tmp/andvari-gradle.lock`.
- **The brand mark has one source: `assets/brand/andvari-mark.svg`.** Every tile icon in the tree
  (web favicon + manifest icons, `extension/icons/*`, `app-desktop/icons/*`) is rendered from it by
  `scripts/gen-brand-icons.sh` — never hand-edit a derivative, re-run the script
  (`scripts/gen-brand-icons.sh --check`, which the release gate runs, fails when a committed
  raster no longer matches a fresh render). **Eight** files cannot be generated and re-draw the
  same geometry by hand, because they are code rather than assets: `web/src/ui/Sigil.tsx`
  BrandSigil, the Android adaptive foreground drawable, the extension popup and options headers
  (inline SVG), `extension/src/popup.ts` and `extension/src/content-ui.ts` (programmatic paths),
  `app-android/.../Theme.kt` (a Compose ImageVector) and `app-desktop/.../Ui.kt` (a Canvas draw).
  Change the geometry and you change ALL of them in the same commit.
  `web/src/ui/brand-assets.test.ts` reads every one and fails when they drift apart, which is how
  the fleet ended up carrying two subtly different runes before 0.27.0.

## Reporting a vulnerability

**Not here, and not in a public issue.** See **[`SECURITY.md`](SECURITY.md)** — GitHub private
advisories are the preferred channel, and the policy covers scope, disclosure, and safe harbour.

## Licensing

Contributions are accepted under the licences in **[`LICENSING.md`](LICENSING.md)**: AGPLv3 for
`server/`, GPLv3 for the clients, `core/`, `tools/`, and the specs and docs.
