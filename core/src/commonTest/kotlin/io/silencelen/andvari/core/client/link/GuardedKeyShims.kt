package io.silencelen.andvari.core.client.link

import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.client.onboard.GuardedKeyPair
import io.silencelen.andvari.core.client.onboard.KeyGuard
import io.silencelen.andvari.core.client.state.AccountStateStore
import io.silencelen.andvari.core.crypto.KeyPairBytes

/** A link account over a test's own keys, which belong to no opened account: one guard of their own. */
fun LinkAccount(
    origin: String,
    emailNorm: String,
    userId: String,
    deviceId: String,
    displayName: String,
    uvk: ByteArray,
    identity: KeyPairBytes,
    signing: KeyPairBytes,
    store: AccountStateStore,
    personalVaultId: String? = null,
): LinkAccount {
    val guard = KeyGuard()
    return LinkAccount(origin, emailNorm, userId, deviceId, displayName, GuardedKey(uvk, guard), GuardedKeyPair(identity, guard), GuardedKeyPair(signing, guard), store, personalVaultId)
}
