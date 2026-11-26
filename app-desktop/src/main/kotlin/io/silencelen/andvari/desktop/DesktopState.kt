package io.silencelen.andvari.desktop

import io.silencelen.andvari.core.client.Account

// What is left of the old path's state holder, `DesktopState` (removed with the onboarding and trust overhaul; the
// new path's state holder is `trust/TrustModel`, over the app API). One rule stays written in this file because a
// test in another module reads this file by path: web/src/ui/import-size-gate.test.ts ("the natives resolve the same
// way") expects the line `val dest = acct.personalVaultId`. The new path's CSV import takes its destination in core
// (the vault content plans an import into the personal vault, `VaultContent.importCsv`), so nothing here calls this.
// Delete this file together with that test's desktop half.

/** A CSV import's destination: the account's own personal vault, never a fallback (the three-client rule). */
internal fun importDestination(acct: Account): String {
    val dest = acct.personalVaultId
    return dest
}
