# andvari spec 00 — overview

This directory is **normative**. The Kotlin implementation (`core/`), the TypeScript
implementation (`web/src/crypto` + sync), and the server (`server/`) follow these
documents; when code and spec disagree, the code is wrong. Changes land here first,
then in `tools/vector-gen` (regenerating `test-vectors/`), then in both
implementations, and `scripts/verify.sh` must green both suites off the same vectors.

## Documents

| Doc | Contents |
|---|---|
| 01-key-hierarchy | KDF, key derivation splits, wrapping, identity keys, password change |
| 02-vault-format | Item/vault data model, AEAD envelope, server-visible plaintext contract, attachments, tombstones, conflicts |
| 03-wire-protocol | Endpoints, sessions, sync state machine, idempotency, WS notify, version pinning |
| 04-escrow-recovery | Org recovery key ceremony, sealed-blob format, canary, recovery + drills |
| 05-threat-model | Assets, adversaries, guarantees, accepted risks, non-goals |
| 06-import-formats | Browser CSV import column maps |

## System shape (informative)

Zero-knowledge, hub-and-spoke, offline-first. Clients (Android, Windows desktop, web)
derive all encryption keys from the user's master password on-device and sync opaque
ciphertext through one ktor server (CT 122 `andvari`, Tailscale-primary, break-glass
public via Cloudflare tunnel + Access). The server orders writes (global revision
counter), stores ciphertext + minimal metadata, authenticates users without ever
seeing the master password, and holds escrow blobs only an **offline** recovery key
can open. Recovery, not the server, is the answer to "forgot my master password."

## Conventions (normative)

- **Encoding of binary in JSON/transport:** base64url (RFC 4648 §5), **no padding**,
  everywhere, with no exceptions. Hex appears only in printed fingerprints.
- **Strings:** UTF-8. **IDs:** UUIDv4 in lowercase canonical text form; wherever an
  ID participates in cryptographic input (AEAD associated data, HKDF info), its
  canonical UTF-8 string bytes are used, never raw 16-byte form.
- **AD/label joining:** components joined with `|` (0x7C). No component may contain
  `|`; conforming components (fixed labels, UUIDs, small integers) cannot.
- **Canonical JSON** (used only where bytes must reproduce, e.g. sealed escrow
  payloads): UTF-8, no insignificant whitespace, object keys in the exact order given
  by the defining spec section, integers in decimal without leading zeros.
- **Versioning:** the protocol namespace is `andvari/v1`. Structures carry explicit
  version fields; parsers MUST reject unknown versions rather than guess.
