# andvari spec 00 — overview

This directory is **normative**. The Kotlin implementation (`core/`), the TypeScript
implementation (`web/src/crypto` + sync), the extension's pure-JS implementation
(`extension/src/crypto.ts`, @noble — the MV3 service-worker CSP forbids WASM), and the
server (`server/`) follow these documents; when code and spec disagree, the code is
wrong. Changes land here first, then in `tools/vector-gen` (regenerating the vectors it
owns — most of `test-vectors/`, but not all: the per-file provenance manifest is
`test-vectors/README.md`), then in every implementation, and `scripts/verify.sh` must
green all three suites off the same vectors.

## Documents

| Doc | Contents |
|---|---|
| 01-key-hierarchy | KDF, key derivation splits, wrapping, identity keys, signed statements and their grammar, the instance card, trust roots and the password rule, the account genesis, domain strings, vault keys, grants and the key commitment, password change |
| 02-vault-format | Item/vault data model, AEAD envelope, server-visible plaintext contract, attachments, tombstones, conflicts, account-state records, the vault log and its client verification |
| 03-wire-protocol | Route index; endpoints, sessions, sync, idempotency, WS notify, version pinning; sign-up and registration; the vault log route; links; device links; the instance card; operator routes; operator-assisted recovery (variant R on the public instance) |
| 04-escrow-recovery | The recovery kit; operator recovery on private instances: the recovery key, consent anchored on the card, the escrow blob, rotations, assisted recovery, drills |
| 05-threat-model | Assets, adversaries, goals, guarantees, accepted risks, non-goals |
| 06-import-formats | Browser + password-manager CSV import column maps |
| 07-export | CSV export dialect + encrypted `.andvari` backup container, restore rules, the cut-over |

`spec/public-instance.json` holds the store-build constants of the public instance
(`PUBLIC_INSTANCE`, the join base, the association hosts); every app's build reads it, and a store
build MUST refuse to ship while any of its values is still a placeholder.

## System shape (informative)

Zero-knowledge, hub-and-spoke, offline-first. Clients (Android, iOS, desktop — Windows `.msi`
and Linux `.deb` from one Compose build — web, MV3 browser extension, `andvari-cli`) derive all
encryption keys from the user's master password on-device and sync opaque ciphertext through
**one ktor server per instance**, on one https origin with a publicly trusted certificate
(`docs/self-hosting.md`). There is a **public instance** (`https://vault.andvaripass.com`, open
sign-up for individuals with a verified email, capped; it does not take sign-ups yet) and any number of **private (family)
instances**; an app talks to one instance at a time. Each instance names itself with an **instance
card** chain signed by its single **operator** account, and clients pin it from a root they can
justify (spec 01 §5.3). People pin each other only through **links** one of them made, confirmed by a
comparison code; every membership and lifecycle change of a shared vault is an entry its owner (or the
leaving member) signs in that vault's **log**, which every device verifies; a device joins an account
through a **device link** and the master password. An instance's declared `ClientPolicy` (spec 03
§1.1) may only make a client *safer*, never laxer. The server orders writes (global revision counter),
stores ciphertext, signed statements and minimal metadata, and authenticates users without ever
seeing the master password. The **recovery kit**, not the server, is the answer to "forgot my master
password"; operator recovery is an opt-in on private instances only (spec 04).

## Conventions (normative)

- **Encoding of binary in JSON/transport:** base64url (RFC 4648 §5), **no padding**,
  everywhere — exceptions: TOTP shared secrets are RFC 4648 base32 (otpauth ecosystem
  requirement, spec 03 §2), and opaque digest fields ride as lowercase hex (attachment
  `sha256`, frame and log hashes, fingerprints, commitments, HIBP range lines — spec 01 §5, spec 03
  §8/§9/§10). Hex otherwise
  appears only in printed fingerprints.
- **Strings:** UTF-8. **IDs:** UUIDv4 in lowercase canonical text form; wherever an
  ID participates in cryptographic input (AEAD associated data, HKDF info), its
  canonical UTF-8 string bytes are used, never raw 16-byte form.
- **AD/label joining:** components joined with `|` (0x7C). No component may contain
  `|`; conforming components (fixed labels, UUIDs, small integers) cannot.
- **Canonical JSON** (used where bytes must reproduce: signed statements, host-minted offers, sealed
  escrow payloads): the strict grammar of spec 01 §5.1 — printable ASCII, no insignificant whitespace,
  object keys in the exact order given by the defining template, integers in decimal without leading
  zeros, a strict parse followed by a re-encode byte-compare.
- **Versioning:** the protocol namespaces are `andvari/v1` (the original key hierarchy and envelopes)
  and `andvari/v2` (signed statements and every label the onboarding and trust design added).
  Structures carry explicit version fields; parsers MUST reject unknown versions rather than guess.
  There is no compatibility with pre-cut-over formats (spec 07 §3.1).
