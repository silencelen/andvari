package io.silencelen.andvari.hostile

import io.silencelen.andvari.core.client.log.VaultLogEngine

/**
 * A copy of a vault's key, for a test to check one is in use: production code never takes one out of the account's guard
 * so this exists only among the tests. The guard refuses a lend that answers a copy of the key
 * (`KeyEscape`), so the copy leaves inside a holder of the test's own: the one shape the guard cannot see.
 */
fun VaultLogEngine.keyFor(vaultId: String): ByteArray? = withKey(vaultId) { KeyCopy(it.copyOf()) }?.bytes

/** A test's own holder of a key copy. */
class KeyCopy(val bytes: ByteArray)

/** A copy of a guarded key, for a test (shipped code has no way to take one). The caller zeroes it. */
fun io.silencelen.andvari.core.client.onboard.GuardedKey.copyOut(): ByteArray = use { KeyCopy(it.copyOf()) }.bytes
