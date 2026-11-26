package io.silencelen.andvari.core.client.log

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.client.onboard.GuardedKeyPair
import io.silencelen.andvari.core.client.onboard.KeyGuard
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.trust.Checkpoint

/**
 * The log engine over a test's own keys, which belong to no opened account: one guard of their own (in
 * the app the keys are always the opened account's, under its guard).
 */
fun StoredVaultLogs(
    me: String,
    signer: KeyPairBytes,
    boxKeys: KeyPairBytes,
    uvk: ByteArray,
    client: WireClient,
    crypto: CryptoProvider,
    state: DeviceState,
    account: AccountStateStore,
    host: VaultLogHost,
    clock: () -> Long,
    bundleCheckpoint: (vaultId: String) -> Checkpoint?,
): StoredVaultLogs {
    val guard = KeyGuard()
    return StoredVaultLogs(me, GuardedKeyPair(signer, guard), GuardedKeyPair(boxKeys, guard), GuardedKey(uvk, guard), client, crypto, state, account, host, clock, bundleCheckpoint)
}

/** A copy of a vault's key, for a test to compare: production code never takes one out of the guard. */
fun VaultLogEngine.keyFor(vaultId: String): ByteArray? = withKey(vaultId) { io.silencelen.andvari.core.client.items.KeyCopy(it.copyOf()) }?.bytes
