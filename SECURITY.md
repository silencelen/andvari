# Security policy

andvari is a zero-knowledge password manager: the client trusts no server, including
the reference one. Cryptographic soundness and client-side confidentiality are the
whole product, so security reports are taken seriously and we'd genuinely rather hear
from you.

## Reporting a vulnerability

**Please report privately — do not open a public issue for a security bug.**

- Preferred: **GitHub private vulnerability reporting** —
  <https://github.com/silencelen/andvari/security/advisories/new>
  (this opens a private advisory visible only to the maintainers and you).
- If you cannot use GitHub advisories, open a normal issue titled *"security contact
  request"* with **no details**, and a maintainer will arrange a private channel.

Please include, as far as you can:

- the component and version/commit (server / web / Android / desktop / extension / core),
- a description of the issue and its impact,
- a minimal proof of concept or reproduction steps,
- any suggested remediation.

Encrypted reports are welcome; if you need a key, ask in the advisory and we'll provide
one.

## Scope

**In scope** — the andvari source in this repository: the server, the clients (web,
Android, desktop, extension), the shared `core` crypto/protocol, the CLI `tools`, and
the specs/test-vectors that define the wire and crypto contracts. We are especially
interested in:

- anything that lets a **server** (including a hostile or compromised one) learn or
  weaken a client's secrets — the zero-knowledge boundary is the crown jewel
  (see `docs/design/` and `spec/`);
- cross-tenant / cross-origin data exposure, namespace or token bleed across a server
  switch, and the anti-phishing trust gate;
- key-at-rest, quick-unlock, recovery/escrow, and offline-cache handling;
- authentication, invite/enrollment, and rate-limit bypasses.

**Out of scope** — the operation of any *particular* deployment (a self-hoster's
server hardening, TLS/reverse-proxy config, or infrastructure), third-party
dependencies' own vulnerabilities (report those upstream; tell us if andvari uses them
unsafely), spam/DoS that requires implausible resources, and reports generated solely
by automated scanners without a demonstrated impact.

## Supported versions

andvari ships from `main`; only the latest released version of each component is
supported. Fixes land on `main` and go out in the next release. (Version fields:
`ANDVARI_CLIENT_VERSION` / the per-client manifests.)

## Disclosure

This is a small project — we aim to acknowledge a report within a few days and to fix
confirmed issues promptly, but cannot commit to enterprise SLAs. We support
**coordinated disclosure**: we'll agree a timeline with you and credit you (if you
want credit) when the fix ships. Please give us a reasonable window before any public
write-up.

## Safe harbor

We consider good-faith security research that respects this policy — not accessing or
modifying other users' data beyond what a proof of concept needs, not degrading the
service for others, and not exfiltrating data — to be authorized, and we will not
pursue or support legal action against it. If in doubt, ask first in a private
advisory.

A machine-readable summary is served at `/.well-known/security.txt` (RFC 9116).
