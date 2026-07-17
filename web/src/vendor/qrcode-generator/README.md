# Vendored: qrcode-generator 1.4.4

QR encoder by Kazuhiko Arase (<https://github.com/kazuhikoarase/qrcode-generator>),
MIT (see `LICENSE`; "QR Code" is a registered trademark of DENSO WAVE). Vendored, not
depended on: zero-dep, frozen upstream (1.4.4 since 2020), and a password manager
should not take supply-chain exposure for 2 KB of matrix math. `web/package.json` is
deliberately untouched.

## Provenance (pinned)

Fetched 2026-07-07 via `npm pack qrcode-generator@1.4.4`.

| artifact | sha256 |
| --- | --- |
| `qrcode-generator-1.4.4.tgz` (npm tarball) | `ab6ed47d378877441deae95972e07b2716c26545a735a23aa6b9d442b33026ed` |
| `qrcode.js` (tarball `package/qrcode.js`, byte-identical copy) | `18ae399f81182bc9de916e9c77b195df20cc58d6f2d55a62b085a299f1bf1780` |
| `qrcode.esm.js` (derived — see below) | `d23117de09bde2305e034cd55c19e2e259f6ea6fd9bc27a89deb538ce197ce30` |
| `LICENSE` (upstream repo tag `v1.4.4`; the npm tarball ships none) | `3a850fa5f08101db6f40676c2786e10bd2cd5fff7b12ffdf1e0c434d4e49d90c` |

## Files

- `qrcode.js` — the pristine upstream UMD file, kept byte-identical for diffing
  against upstream. Not imported by anything (UMD exports nothing under ESM).
- `qrcode.esm.js` — the runtime copy. Mechanical 2-part derivation from `qrcode.js`
  (enforced byte-exactly by `integrity.test.ts`): (1) the UMD footer's CommonJS branch
  (`else if (typeof exports === 'object') { module.exports = factory(); }`) is REMOVED —
  vitest 3's module runner supplies interop `exports`/`module` globals, so upstream's
  assignment executed under tests and collided with the read-only ESM namespace;
  (2) a marked ESM epilogue (`export default qrcode;`) is appended. Nothing else changed.

- `qrcode.esm.d.ts` — types for the shim, narrowed from upstream `qrcode.d.ts`.
- `index.ts` — the ONLY import surface: `qrModules(text, ecc) → boolean[][]`
  (typeNumber 0 auto-size, UTF-8 byte mode). Import nothing else from this dir.

## Tamper checks

- `sha256sum qrcode.js qrcode.esm.js` against the table above.
- `web/src/vendor/qrcode-generator/qrmodules.test.ts` pins the sha256 of the
  encoder's output matrix for a golden otpauth URI (behavioral pin), and a jsqr
  decode round-trip was run at vendor time (batch v6-QW1 log) proving the emitted
  matrices scan back to the exact input strings.
