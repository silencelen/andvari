# Licensing

andvari is dual-licensed by component. The split is deliberate (design
`docs/design/2026-07-16-trust-attestation-strategy.md`, fork **F1**): copyleft as a
security property, so the code a household — or a stranger — actually runs stays
auditable.

| Component | Path(s) | License | SPDX |
|---|---|---|---|
| **Server** | `server/` | GNU Affero GPL v3.0-or-later | `AGPL-3.0-or-later` |
| **Clients** — web, Android, desktop, browser extension | `web/`, `app-android/`, `app-desktop/`, `extension/` | GNU GPL v3.0-or-later | `GPL-3.0-or-later` |
| **Shared core & tools** | `core/`, `tools/` | GNU GPL v3.0-or-later | `GPL-3.0-or-later` |
| **Specs, test vectors, docs** | `spec/`, `docs/` | GNU GPL v3.0-or-later (docs may additionally be reused under CC-BY-4.0) | `GPL-3.0-or-later` |

- **Why AGPL for the server:** the server is offered over a network. AGPLv3 §13
  ("Remote Network Interaction") requires anyone who runs a *modified* andvari server
  as a network service to make that modified source available to its users — the
  property that keeps a hosted instance honest. The clients are distributed as
  binaries, where plain GPLv3's distribution-triggered copyleft already covers them.
- **`core/` is GPLv3** (not AGPL) even though the server links it: GPLv3 and
  AGPLv3 are explicitly compatible for combination (GPLv3 §13 / AGPLv3 §13), so the
  AGPL server may incorporate the GPL core, and the GPL clients are never burdened
  with the server's network clause.
- **Full texts:** repository-root `LICENSE` (GPLv3, canonical) and `server/LICENSE`
  (AGPLv3). Third-party dependencies keep their own licenses (see each package's
  manifest / `THIRD-PARTY` notices where present).

## Before publishing (flip checklist)

- [ ] **`server/LICENSE`** currently carries an AGPLv3 *declaration* with a flagged
      placeholder — paste the verbatim canonical text from
      `https://www.gnu.org/licenses/agpl-3.0.txt` (it was not available offline; do
      not hand-transcribe a legal document).
- [ ] Confirm F1 is still the intended split (owner may overturn at pickup, per the
      trust-attestation doc).
