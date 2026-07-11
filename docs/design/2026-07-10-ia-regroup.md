# DN-2 + IA re-grouping (owner dev-note pair, 2026-07-10)

**Owner:** (1) "instead of having our 'trash' page have its hyperlink in the main menu, lets
have a small trash icon on the vaults page, as well as changing the 'trashed vaults' section
to being a trash icon on the sharing page." (2) "lets also take this as a chance to look
through how we are presenting, and grouping pages and content. weve added little pieces and
extra sections on since first designing the layout."

Two full IA inventories (web + native, line-cited) back this doc. **Tier 1 ships now** (the
dev-note itself + same-species, fact-backed fixes). **Tier 2 is pitched, not shipped** — nav
taste belongs to the owner; each pitch has a size and a default so a "go" is one word.

## Tier 1 — shipping in 0.11.1

1. **Web: Trash leaves the main nav → a small trash icon on the vaults toolbar** (nav 6→5;
   the nav already overflow-scrolls on mobile). TrashView itself unchanged (Back behavior
   already correct: any non-vault view falls back to vault). Web has no icon library — a
   tiny inline-SVG trash glyph in the house sigil idiom, aria-labelled.
2. **Web + Android: the trashed-vaults section goes behind a trash icon on Sharing.**
   Web: ViewHeader's `actions` slot (F80) gets the icon; it toggles a DISCLOSURE (deliberately
   NOT another back-guard layer — a collapsed section needs none of DN-1's machinery), with
   `RecentlyDeleted` moved verbatim inside the conditional. Android: the Sharing TopAppBar
   (list mode) gets a trash action icon toggling a `rememberSaveable` disclosure.
   **Small intentional extension:** Android's sibling break-glass section "Recently removed"
   (the holding area) moves behind the SAME disclosure — hiding "deleted" while the rarer
   "removed" stays always-on would be incoherent; one icon = "deleted & removed vaults".
3. **Phantom-pointer copy fix (a shipped bug the inventory caught):** web notice copy and a
   store doc-comment say "Settings → Recently removed" — **no such surface exists anywhere on
   web** (the store tracks held vaults; no UI lists them). Web copy drops the pointer (plain
   "kept on this device for 30 days"); Android's copy (which points at a real surface) updates
   to name the new trash icon. The missing web holding-area surface itself is Tier 2 (net-new
   UI, not a move).
4. **Naming disambiguation:** "Recently deleted" currently titles BOTH deleted items (Trash
   view, all 3 clients) and deleted vaults (Sharing). Trash surfaces retitle to **"Trash"**
   (matches the icon + concept, all 3 clients); the Sharing section becomes **"Recently
   deleted vaults"**. Title strings only — listed intentional edits.
5. **Android lock-guard omission (real bug, 1 line):** `checkIdleLock`'s locked-underneath
   reflection lists Vault/Sharing/Settings/AutofillStatus but omits **Trash** — a Trash
   screen left open when the autofill gate locks the session underneath doesn't kick to the
   lock screen. Add `Screen.Trash`.

Dropped from Tier 1 after tree-verification: web `+ Card` is already hidden (not dark) — the
web inventory over-claimed; nothing to do.

## Tier 2 — pitched for ratification (defaults stated; nothing here ships without a "go")

- **P1 Nav consolidation (web).** After Tier 1 the nav is Vault · Sharing · Health · Settings
  · Admin. Pitch: Health→a toolbar icon beside the new trash icon (it's an occasional tool,
  not a place), leaving Vault · Sharing · Settings · Admin. Size S. Default if silent: leave.
- **P2 Devices install-hub out of Settings.** A 231-line feature is Settings' last card (its
  QR already hidden-by-default for dominating). Pitch: its own view reachable from a Settings
  row ("Get andvari on your devices →"), symmetric with how AutofillStatus works on Android.
  Size S-M. Default: leave.
- **P3 Make the Settings backup card actionable.** Today it shows the date and tells you to go
  to the toolbar. Pitch: the card gains the two export buttons (same ExportPanel layer).
  Size S. Default: leave (3 entry points is odd; 1 passive card is odder).
- **P4 Notice/banner system.** Web stacks 4 global banners in 4 visual idioms; Android mounts
  three break-glass cards (ReSeal, unopenable-vault, lifecycle/transfer) on the DAILY vault
  list, and lifecycle/transfer banners render on TWO screens at once. Pitch: one visual idiom
  + a placement policy (break-glass cards collapse to one compact attention line on the daily
  list, expanding where they belong). Size M and OPINIONATED — needs the owner's eye.
- **P5 Android update-available + 426 parity.** Desktop-only today; Android has no
  app-update banner and no minVersion screen at all (devstore banner exists, in-app signal
  doesn't). Feature gap more than IA. Size S-M. Default: build soon.
- **P6 Server URL visibility.** Lives only on the signed-out Welcome; invisible once signed
  in. Pitch: read-only display in Settings ("Server: … — sign out to change"). Size XS.
  Default: build with P2.
- **P7 Two "TOTP"s.** Item one-time codes vs server 2FA share a word. Pitch: retitle the
  Settings card "Two-factor sign-in (server)". Size XS. Default: build with any Settings pass.
- **P8 Header/toolbar unification.** ViewHeader (built to unify, 0.10.0) reaches 4 of ~11
  surfaces; Android/desktop toolbar icon ORDERS differ (sync 2nd vs 4th). Plus the missing
  web holding-area surface (see Tier 1 §3). Size S each, mechanical. Default: fold into the
  next polish cycle.

## Tier-1 regression notes (for the review)

- `RecentlyDeleted` / `RecentlyDeletedSection` / `RecentlyRemovedSection` move VERBATIM inside
  disclosures (title strings excepted, listed above). The restore path keeps threading
  `deleteId`. Their refresh mechanics tolerate remount (verified in the DN-1 breaker pass:
  remount refetches).
- Disclosures are presentation state only (web `useState`, Android `rememberSaveable`) — no
  VM/store state, no back-guard interaction, closing loses nothing (the sections are
  read-and-act lists, no in-flight local ops).
- Web nav removal must not strand `view === "trash"`: reachable only via the new icon; Back
  from Trash falls to vault exactly as before (closeTop's view fallback).
- Android TopAppBar actions render ONLY in list mode (settings-reveal mode keeps its back
  arrow + title contract from DN-1).
