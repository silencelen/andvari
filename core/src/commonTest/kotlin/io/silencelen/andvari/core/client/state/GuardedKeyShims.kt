package io.silencelen.andvari.core.client.state

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.onboard.GuardedKey
import io.silencelen.andvari.core.crypto.CryptoProvider

/** The account-state store over a test's own UVK, which belongs to no opened account: a guard of its own. */
fun StoredAccountState(
    userId: String,
    uvk: ByteArray,
    client: WireClient,
    crypto: CryptoProvider,
    state: DeviceState,
    maxAttempts: Int = 4,
    limits: AccountLimits = AccountLimits.DEFAULT,
): StoredAccountState = StoredAccountState(userId, GuardedKey.loose(uvk), client, crypto, state, maxAttempts, limits)
