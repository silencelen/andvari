package io.silencelen.andvari.core.client.log

/*
 * The engine's withdraw and re-post act only on the change the caller names by the hash of its signed entry. Tests that
 * act on whatever is held at that moment (as a screen drawn at that very moment would name it) use these.
 */

/** [StoredVaultLogs.withdraw] of the change held for [vaultId] as it is at rest now. */
internal suspend fun StoredVaultLogs.withdrawAsHeld(vaultId: String): HeldWithdrawal = withdraw(vaultId, heldEntryHash(vaultId).orEmpty())

/** [StoredVaultLogs.repostHeld] of the change held for [vaultId] as it is at rest now. */
internal suspend fun StoredVaultLogs.repostAsHeld(vaultId: String): HeldRepost = repostHeld(vaultId, heldEntryHash(vaultId).orEmpty())
