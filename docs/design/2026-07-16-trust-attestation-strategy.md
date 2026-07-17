# andvari — public-release trust & attestation strategy (design, 2026-07-16)

> Status: DRAFT for owner ratification — **orchestrator pickup planned.** Source: interactive
> strategy session 2026-07-16 (tmux `andvari3rdpart`), grounded against spec 02 §5 / spec 05 at
> HEAD `30bdc22`. Companion docs (this one deliberately does NOT re-decide anything they settled):
> `2026-07-15-multi-tenant-endpoints.md` (the self-hostable / endpoint-agnostic pivot — owner
> decisions locked) and the internal pre-publication secret scan (2026-07-16, held privately in `andvari-internal`; safe-to-publish
> verdict: SAFE-AFTER-TREE-FIXES, no mandatory history scrub). Scope here = the **outward-facing
> trust story once the repo is public**: what proves, to a stranger, that the cryptography does
> what we say and that the publisher (and any server operator) sees exactly what spec 02 §5 says
> and nothing more.

## 1. Trust thesis

The model (household reference instance + public source + self-hosting first-class) means we
never ask strangers to trust our *server* — so the entire third-party question collapses to
three independently verifiable properties:

| # | Property | How a stranger verifies it |
|---|---|---|
| P1 | **The design is sound** | Public normative spec (00–07) + community review + eventually one named-firm audit of specs 01/02/04 + `core/` + the client crypto twins, report published verbatim |
| P2 | **Published binaries match the public source** | Signed artifacts + CI build provenance (SLSA attestations) + reproducibility where feasible |
| P3 | **The client leaks nothing to whatever endpoint it points at** | The wire-egress harness (§W2): a runnable, in-repo proof that every outbound field is on the spec 02 §5 whitelist — self-hosters run it against their own endpoint |

The headline claim writes itself and is already *implemented*, not aspirational: **"the client
trusts no server, including ours."** T1 (server compromise) is the design's founding adversary,
and the same fences protect a user pointing at a sketchy self-hosted VPS: the H1 KDF floor at
the ingestion boundary, AD binding (no ciphertext slot-swaps), T10 triple pinning + human
fingerprint check, verifier-only auth, and the pivot's B1-1 policy clamps ("a server may make a
client safer, never laxer").

**Honest caveats are part of the claim, not exceptions to it** — the whitepaper certifies the
boundary rather than papering over it: R3 (the org recovery-key holder CAN decrypt
`required`-policy members — ZK is toward the *server*, not the recovery-key holder), R4/A6
(metadata: who syncs when, item counts, sizes), T6 (web page-load trust; natives are the trust
anchor).

**Explicit non-goals** (record once, cite forever):
- **SOC 2 / ISO 27001** — attest an *operator's* org controls; we don't operate a service for
  strangers. Dead unless andvari is ever sold to businesses.
- **PCI DSS** — binds merchants/service providers in the card-*processing* chain. A user storing
  their own card in an E2E-encrypted vault the publisher cannot decrypt puts the publisher
  outside the cardholder-data environment (the 1Password/Bitwarden posture). The public
  statement: *"card data is encrypted client-side under keys the operator never possesses;
  andvari is not a payment processor and no PCI-scoped system exists."* Backing controls already
  shipped: the A7 capture/save gate (PAN/CVV-save bug closed 2026-07-15) and backup-cli
  `number`/`securityCode`/`notes` redaction (M6).
- **Internal AI-driven audits as public evidence** — the 07-13 pentest and 07-15 ASVS L2 review
  are real engineering process but are *self*-audit; independence is the thing a third party
  buys. They remain our internal bar and (sanitized) transparency artifacts (§W7).

## 2. What already exists (do not rebuild)

- **Spec 02 §5** — the normative server-visible-plaintext table with a change-control rule.
  This IS the whitepaper's core; most commercial vendors have nothing this strong.
- **Spec 05** — a public-quality threat model (T1–T11, R1–R9).
- **`scripts/e2e.sh` PHASE C** — the ciphertext-only tripwire (sentinel present decrypted,
  absent from every stored value via deep raw+base64url scan). §W2 is its wire-capture twin.
- **Signing**: Authenticode MSI + GPG deb (ceremony 2026-07-14,
  `docs/runbooks/release-signing-keys.md`), CWS/AMO store-signing in flight, Ed25519 update
  manifest (being **un-armed** by the pivot — update mechanics defer to that doc; §W4 signs
  whatever artifacts publish, wherever they publish).
- **Secret-scan remediation list** (the internal pre-publication secret scan §4, held privately
  in `andvari-internal`) — the flip gate. Not duplicated here.

## 3. Workstreams (orchestrator lanes)

Each lane is independently shippable; gates are stated so a wave can be find→refute reviewed.

**W1 — Security whitepaper.** Assemble the public whitepaper from specs 00–07 after the pivot's
deployment-genericization sweep (pivot §10 DOCS — "the server", not CT 122). Dual-register
(lay summary over normative detail); embeds the spec 02 §5 table verbatim, the trust thesis +
caveats of §1, and the PCI/SOC2 non-goal statements. *Gate:* every claim traceable to a spec
section or a named test; no claim about the web client stronger than T6 allows.

**W2 — Wire-egress harness (flagship).** Proxy-instrumented run (mitmproxy or equivalent)
exercising every client flow against a disposable server; assert **every field of every
outbound payload** against the spec 02 §5 whitelist, fail-closed on any unrecognized
field/header/param. Ships in `tools/` with a CI job; README section tells self-hosters how to
run it against their own endpoint. Builds on PHASE C's fixture patterns. *Gate:* non-vacuity —
the harness must go RED on a deliberately planted leak (a plaintext field smuggled into a
payload) and GREEN at HEAD; coverage list of exercised flows checked against spec 03's endpoint
table.

**W3 — Repo security tooling (activates at the public flip).** CodeQL + Dependabot + secret
scanning w/ push protection + branch protection; `SECURITY.md` + `/.well-known/security.txt`
on the reference instance + a disclosure policy (GitHub Security Advisories for CVE handling
going forward); OpenSSF Scorecard; SBOM (CycloneDX via Syft) attached to each release — the
tiny dependency footprint (libsodium, @noble, tweetnacl, ktor) is itself a trust asset, make it
inspectable. *Note:* Actions is free for public repos, which should sidestep the account
billing block seen on private repos — verify on first workflow run. *Gate:* Scorecard run
recorded; a canary secret push is blocked; SECURITY.md contact path tested.

**W4 — Artifact provenance.** GH Actions release builds with **artifact attestations** (SLSA
provenance: artifact ⇒ commit ⇒ workflow) + signed sha256SUMS per release, layered on the
existing GPG/Authenticode signatures. Reproducibility is a long-tail goal, not a gate:
deb/APK/web bundle feasible; MSI stays a documented manual Windows-box build, Authenticode
only. **Reconcile with pivot B2-4** (which routes the server image via public GHCR and client
artifacts via the reference `/downloads`): recommendation = **GitHub Releases as canonical**
for client artifacts with `/downloads` as the household mirror, so strangers' downloads and
update checks don't ride the household box (availability + targeted-update surface) — fork F3.
*Gate:* `gh attestation verify` passes on a published artifact; SUMS file signature verifies
against the published release key.

**W5 — Fuzzing + differential testing.** Jazzer (JVM) over the risk-ranked parsers: import
formats (spec 06), the AEAD envelope / vault format, wire DTOs, the `.andvari` backup
container. Differential fuzzing Kotlin ↔ TS ↔ @noble off a shared corpus (extends the
cross-impl vector suite; the metaV parse fork class, automated). ClusterFuzzLite in CI;
OSS-Fuzz application only if adoption ever warrants. *Gate:* each fuzz target proves itself on
a known-bad seed (e.g. a truncated FINAL chunk); corpus checked in; CI budget bounded.

**W6 — External audit path (owner-gated, post-flip).** Once public: **OSTIF application**
(free sponsored audits for open-source security projects; selective, queued — costs only the
application). When real external users exist: a scoped named-firm engagement — Cure53 is the
de-facto standard for this product class (Bitwarden annually, Proton Pass, NordPass, Mullvad);
alternates with crypto depth: Least Authority, Doyensec, Trail of Bits, NCC Crypto Services.
Minimal meaningful RFP scope (~1–2 person-weeks, ~$15–50k): (1) design review specs 01/02/04;
(2) implementation review `core/` crypto + the three client crypto twins + server auth;
(3) **dynamic ZK verification** — auditor independently proxies all client traffic and attests
the spec 02 §5 table empirically (W2 hands them the harness); (4) report published **verbatim**
+ our fix log (findings-then-fixes reads as more credible than a clean report). *Gate:* owner
budget sign-off; report publication is a precondition of the engagement, in the RFP.

**W7 — Posture-document publication.** Decide-and-execute publishing *sanitized* versions of
the pentest (2026-07-13) and compliance (2026-07-15) reports: transparency asset once every
in-scope finding is closed. Requires the secret-scan §3 identifier scrub (tailnet, RFC1918,
host names, drill/deployment state) and closure/annotation of the still-open M-items the raw
report advertises. *Gate:* a fresh grep-sweep for the scan §3 identifier list returns zero on
the published copies; every finding row carries a fixed/accepted disposition.

## 4. Owner forks (recommended defaults — announced-default pattern; overturn any at pickup)

| # | Fork | Recommended default | Rationale |
|---|---|---|---|
| F1 | License | **GPLv3 clients + AGPLv3 server** (Bitwarden precedent) | Copyleft as a *security* property: a hostile fork can't go closed and quietly add exfiltration while riding the project's reputation. Permissive maximizes adoption but gives exactly that up. |
| F2 | Git history at the flip | **Publish full history** after the scan §4 tree fixes | The scan verified nothing rotatable/secret in history; open development history is itself provenance (P2). Residual = low-severity PII-in-history + infra fingerprinting the scan shows is only partially retractable anyway (shipped APKs, CT logs). Squash only if the owner wants the PII judgment call closed hard. *(Supersedes the fresh-root-cut lean from the pre-scan discussion — the scan's evidence is strictly better.)* |
| F3 | Canonical client-artifact home | **GitHub Releases canonical, reference `/downloads` = household mirror** | Strangers' download/update traffic shouldn't depend on (or target) the household box. Needs reconciliation with pivot B2-4's `/downloads` rollout step in the same wave. Server image stays GHCR per the pivot. |
| F4 | Publish sanitized audit reports | **Yes** (after W7 gates) | Findings-then-fixes transparency beats silence; precedent set by every serious vendor's audit page. |

One deliberate keep, stated for the record: **clients pin the publisher's update/release keys
regardless of which server they sync with** — a self-hosted server operator gets no update
authority over their household's clients. Document it in W1; it's a real security property of
the design (and survives the pivot's un-arming of the auto-check, since it governs artifact
verification wherever updates come from).

## 5. Sequencing

- **Pre-flip, private:** W1 drafting and W2/W5 builds can start now (W1 depends on the pivot's
  §10 DOCS genericization sweep landing first). The flip itself is gated by the secret-scan §4
  MUSTs (CF tunnel-token rotation · PII fixture sweep + vector regen · `.pyc` untrack) + the
  pivot's tailnet-scrub release gates — those lists live in their own docs.
- **At the flip:** W3 (tooling switches on), W4 (first attested release), F1/F2 execute.
- **Post-flip:** W7 when its gates clear; W6 OSTIF immediately, named-firm audit when external
  users are real.
