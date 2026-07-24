/**
 * Item formatVersion discipline (spec 02 §3; docs/design/2026-07-09-cards-wallet.md) — the
 * extension's slice of the fleet-wide per-doc-floor contract. Chrome-free on purpose: the web
 * vitest suite imports these values (web/src/extension-pins.test.ts), so neither can drift by
 * accident — changing a value must break that pin first, deliberately.
 *
 * The rules background.ts implements with these:
 *  - READ fails closed above MAX_ITEM_FORMAT_VERSION — an fv this client doesn't understand
 *    may carry doc semantics an edit would corrupt (fv 2 = cards: we can decrypt them, list
 *    them in the popup, and copy their fields).
 *  - NEW LOGINS seal at LOGIN_FORMAT_VERSION (the login doc floor); NEW CARDS (G2 save-card
 *    banner, design 2026-07-23 §G2 [X2-A6]) seal at CARD_FORMAT_VERSION via a card-aware seal
 *    path — the extension now creates logins AND cards (never notes).
 *  - RE-SEALS carry the fv the item was decrypted at (kept per-item on the session) and seal +
 *    AD-bind at max(LOGIN_FORMAT_VERSION, carried) — the monotonic client rule (web
 *    Account.itemFv parity). The server refuses per-item fv downgrades; the whole fv2 design
 *    rests on "no fielded client legitimately downgrades — and none gratuitously UPgrades
 *    logins", so both directions are locked here.
 */

/** Highest item formatVersion this client can decrypt (read ceiling — fail closed above). */
export const MAX_ITEM_FORMAT_VERSION = 2;

/** The per-doc floor for a login doc — the fv every NEW login seals at. Logins/notes stay
 *  fv 1 fleet-wide (only card-bearing docs floor at 2); bumping this would be the gratuitous
 *  login upgrade the rest of the fleet never expects. */
export const LOGIN_FORMAT_VERSION = 1;

/** [X2-A6] The per-doc floor for a card doc — the fv every NEW card seals at, and the floor a
 *  card UPDATE re-seals at (max(CARD_FORMAT_VERSION, target.formatVersion)). Card-bearing docs are
 *  fv 2 fleet-wide; the G2 save-card path is the extension's FIRST card writer (background.ts
 *  putNewCard/putCard — the card-aware seal path, distinct from the login putExisting/putNewLogin). */
export const CARD_FORMAT_VERSION = 2;
