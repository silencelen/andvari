package io.silencelen.andvari.core.client.deletion

import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.onboard.GuardedKeyPair
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.trust.VaultState

/** Account deletion over a test's own signing key, which belongs to no opened account: a guard of its own. */
fun WireAccountDeletion(
    me: String,
    emailNorm: String,
    signer: KeyPairBytes,
    client: WireClient,
    crypto: CryptoProvider,
    reauth: Reauth,
    verifiedState: (String) -> VaultState?,
    clock: () -> Long,
    onDeleted: suspend () -> Unit,
): WireAccountDeletion = WireAccountDeletion(me, emailNorm, GuardedKeyPair.loose(signer), client, crypto, reauth, verifiedState, clock, onDeleted)

/** As above, its leaves placed from [logs]' own verified state. */
fun WireAccountDeletion(
    me: String,
    emailNorm: String,
    signer: KeyPairBytes,
    client: WireClient,
    crypto: CryptoProvider,
    reauth: Reauth,
    logs: StoredVaultLogs,
    clock: () -> Long,
    onDeleted: suspend () -> Unit,
): WireAccountDeletion = WireAccountDeletion(me, emailNorm, GuardedKeyPair.loose(signer), client, crypto, reauth, logs, clock, onDeleted)
