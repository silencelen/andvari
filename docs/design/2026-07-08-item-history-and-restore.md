# Design — Item History & Restore ("the fat-finger seatbelt")

**Status:** v6 exploration-lane feature. Batch 1 (server route + core decode + tests + spec text +
this doc) then batch 2 (web History panel). Selected as the idea-tournament #1 (4/5-lens
convergence) — `docs/design/2026-07-08-v6-idea-tournament.md`. Resolves backlog **F63** (and answers
**SB-3**/**F62**: once history ships, `passwordHistory` is redundant → mark reserved, not built).

## The problem

The server has **silently archived the last 10 ciphertext versions of every item** on every
overwrite and every delete since v1 (`Repo.archiveVersion` — INSERT-or-replace into `item_versions`
then prune to the 10 newest revs; `Service.applyPut`/`applyDelete` call it *before* rewriting or
tombstoning). No route or client can reach a byte of it — F63 calls it "spec-promised backstop as
unreachable ciphertext." A household member who rotates the Netflix/bank password and fat-fingers
the save has today no recovery short of a PBS restore drill.

## What v1 ships (first slice)

1. **`GET /api/v1/items/{id}/versions`** — additive, grant-checked (mirrors the attachment-GET auth:
   `requirePrincipal` → look up the item's `vaultId` → `grantRole` → 403-hidden on no grant / no
   item, per spec 03 §8). Returns the archived versions newest-first: `[{rev, blob, formatVersion,
   archivedAt}]` (a new additive `ItemVersion` wire DTO — no DB schema change; `item_versions`
   already exists and is pruned).
2. **Client-side decode** — the client decrypts each version's `blob` under the **VK it already
   holds**. The item envelope's AD binds `(vaultId, itemId, formatVersion)` — **not `rev`** — so an
   old envelope opens with the current key and **zero crypto changes** (verified: `Ad.item` /
   `Account.decryptItem`). The client supplies `vaultId` (known from the live item) since the
   version DTO deliberately carries no vault-identifying field.
3. **Restore = a plain put over the live item** — choosing a historical version and saving it is an
   ordinary `saveWithUploads`/put; no new server semantics, no new state. Restore is offered **only
   on items that still exist live** (see the undelete cut below).
4. **Web History panel** (batch 2) — per-version reveal + "Restore this version", labelled honestly
   ("up to the last 10 versions") — never "nothing is ever lost". Android/desktop panels are a later
   slice (the core `itemVersions` + decode land now so every client can build on them).

## Zero-knowledge posture (unchanged)

The server stores nothing new and learns nothing new — the versions were already written, pruned,
and listed in the spec §5 table. Decryption is entirely client-side under the member's existing VK.
The route is grant-checked exactly like the live item and attachments. No wire-format bump, no
`formatVersion` bump, no new plaintext to the server.

## The invariant this feature HANDS to the queued VK-rotation design (do not skip)

`item_versions.blob` is ciphertext under the vault's **current** VK. The queued **lazy VK rotation**
(ROADMAP:126) will re-wrap live items under a new VK — but the *archived* versions are sealed under
the **old** VK. After a rotation, pre-rotation history becomes **undecryptable** unless the rotation
design explicitly handles it. This design commits to the honest, cheap contract:

> **History resets at VK rotation.** v1 does NOT re-encrypt the archive on rotation; the panel shows
> only versions sealed under the current VK, and the copy says so. The VK-rotation design MUST
> either (a) accept this reset and prune `item_versions` for the rotated vault at rotation time (so
> no undecryptable rows linger and mislead), or (b) if unbroken history is later deemed required,
> re-encrypt or dual-seal the archive as part of rotation — a strictly larger piece to be priced
> THEN, not assumed now. Either way, the two features must not ship mutually broken; this note is
> the hand-off.

## Explicitly CUT from v1 (where the L-complexity hides — deferred, not abandoned)

- **Undelete / "Recently deleted" / Trash.** Clients **hard-drop tombstones on ingest**
  (`store.ts` pull loop / `SyncEngine` — a tombstone removes the item from the live set), so a
  deleted item isn't reachable to even ask for its versions. Undelete needs an unpitched
  **tombstone-enumeration route** + **restore-marker server semantics** + a Trash view — its own
  slice after history proves the panel, and after F49 decides the retention window. The route below
  is written to serve a tombstoned item's versions too (the item row persists with its `vaultId`),
  so undelete builds on it without a redesign.
- **Diff/change summarizer** between versions — pure UI polish, later.
- **F62 `passwordHistory` fold** — item_versions makes the per-item field largely redundant; the
  SB-3 answer is "mark spec/02 `passwordHistory` reserved," an owner decision, not a rider here.

## Cost / batches

- **Batch 1 (this):** `GET /items/{id}/versions` + `ItemVersion` DTO + `AndvariApi.itemVersions` +
  `Account.decryptItemVersion` + server route test + core decode test + spec 02 §7 / 03 text + this
  doc. M, additive, no schema/crypto/version change.
- **Batch 2:** web History panel (per-version reveal + restore-on-live-items). Reviewed separately.
- Android/desktop History panels + undelete/trash are subsequent slices.
