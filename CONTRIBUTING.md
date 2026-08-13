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
(cd web && npm install)
(cd extension && npm install)
bash scripts/verify.sh
```

You need **JDK 17**, **Node ≥ 22**, and — because `verify.sh` includes the Android client — an
**Android SDK**, found via `ANDROID_HOME` or an `sdk.dir` line in `local.properties`. Without one,
run the suites individually and skip the `:app-android` line; everything else stands alone.

`scripts/verify.sh` is the gate every release goes through. In order, it:

1. **Release-version consistency** — core, Android, desktop, and web must all report the same
   client version, and the top `CHANGELOG.md` heading must name it. One skew fails the gate.
2. **Endpoint-agnostic docs** — no reference-instance hostname in the current-facing docs, the
   prose half of the rule the clients are pinned to (`spec/05` §5.5). Dated design records under
   `docs/design/` are exempt: they are history, not instructions.
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
six (`card`, `cardfill`, `cardform`, `enrolllink`, `import-foreign`, `urimatch-etld1`) are
hand-authored fixtures. Both engines consume all of them either way.

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

## Reporting a vulnerability

**Not here, and not in a public issue.** See **[`SECURITY.md`](SECURITY.md)** — GitHub private
advisories are the preferred channel, and the policy covers scope, disclosure, and safe harbour.

## Licensing

Contributions are accepted under the licences in **[`LICENSING.md`](LICENSING.md)**: AGPLv3 for
`server/`, GPLv3 for the clients, `core/`, `tools/`, and the specs and docs.
