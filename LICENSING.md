# Licensing

andvari is dual-licensed by component. The split is deliberate (design
`docs/design/2026-07-16-trust-attestation-strategy.md`, fork **F1**): copyleft as a
security property, so the code a household — or a stranger — actually runs stays
auditable.

| Component | Path(s) | License | SPDX |
|---|---|---|---|
| **Server** | `server/` | GNU Affero GPL v3.0-or-later | `AGPL-3.0-or-later` |
| **Clients** — web, Android, iPhone, desktop, browser extension | `web/`, `app-android/`, `app-ios/`, `app-desktop/`, `extension/` | GNU GPL v3.0-or-later (the iPhone app with the additional permission below) | `GPL-3.0-or-later` |
| **Shared core & tools** | `core/`, `tools/` | GNU GPL v3.0-or-later | `GPL-3.0-or-later` |
| **Specs, test vectors, docs** | `spec/`, `docs/` | GNU GPL v3.0-or-later (docs may additionally be reused under CC-BY-4.0) | `GPL-3.0-or-later` |
| **Name and marks** | `assets/brand/`, and the icons rendered from it | The licenses in this table cover the code. They do not grant rights to the name andvari, the rune mark or the drawn wordmark: see `assets/brand/BRAND.md`, "The marks and the licenses". The two typefaces named there keep their own license (`assets/brand/OFL-EBGaramond.txt`, `assets/brand/OFL-AlegreyaSans.txt`). | — |

- **Why AGPL for the server:** the server is offered over a network. AGPLv3 §13
  ("Remote Network Interaction") requires anyone who runs a *modified* andvari server
  as a network service to make that modified source available to its users — the
  property that keeps a hosted instance honest. The clients are distributed as
  binaries, where plain GPLv3's distribution-triggered copyleft already covers them.
- **`core/` is GPLv3** (not AGPL) even though the server links it: GPLv3 and
  AGPLv3 are explicitly compatible for combination (GPLv3 §13 / AGPLv3 §13), so the
  AGPL server may incorporate the GPL core, and the GPL clients are never burdened
  with the server's network clause.
- **The iPhone app carries one additional permission** (GPLv3 §7). Apple's terms for
  the App Store restrict what a person may do with an app received there, and GPLv3
  §10 does not let a distributor add restrictions of its own. The copyright holder is
  not bound by that; anyone else who builds the iPhone app from this source would be.
  So: *As an additional permission under section 7 of the GNU General Public License,
  version 3, the copyright holder permits you to convey the iPhone app (the work built
  from `app-ios/` together with the parts of this repository that are compiled or
  bundled into it) through Apple's App Store, although the App Store's terms place
  restrictions on the people who receive it there that the License does not otherwise
  allow a distributor to impose; this permission covers conveying through the App Store
  only, and whoever conveys the app there must still make its corresponding source
  available under the License.*
- **Full texts:** repository-root `LICENSE` (GPLv3, canonical) and `server/LICENSE`
  (AGPLv3). Third-party dependencies keep their own licenses (see each package's
  manifest / `THIRD-PARTY` notices where present).

## Status

The F1 split above is in effect: both canonical texts are in the tree — root `LICENSE`
(GPLv3) and `server/LICENSE` (the verbatim GNU AGPLv3 from spdx/license-list-data,
2026-07-16; §13 Affero clause verified) — and the repository was published under them.
The trust-attestation doc reserved the option to revisit the split; nothing has revisited
it since.

The iPhone app's place in the table and its additional permission were added on
21 November 2026. Until then the table did not name `app-ios/`, and only the root
`LICENSE` applied to it.
