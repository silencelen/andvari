package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.UsageRecorderCore
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.UsageKey
import io.silencelen.andvari.core.model.wire.UsagePut
import io.silencelen.andvari.core.model.wire.UsageResponse
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute

/**
 * The usage ledger's store on the new session (spec 02 §8.2, spec 03 §3): the four operations
 * [UsageRecorderCore] needs, over the session's [WireClient]. The ledger is sealed under a key derived from the PERSONAL
 * vault key, with the AD `andvari/v1|usage|{userId}`, so it follows the account genesis like everything else personal:
 * with no personal vault in force ([VaultKeySource.personalVaultId] null) there is no ledger, and [open] and [seal]
 * throw, which the recorder treats as "no ledger", never as an empty one. The prune keep-set is
 * [ItemEngine.liveItemIds].
 *
 * [halted]: under a fork of the origin's card chain (design §4.4) nothing is fetched or stored.
 */
class SessionUsage(
    private val client: WireClient,
    private val keys: VaultKeySource,
    private val crypto: CryptoProvider,
    private val userId: String,
    private val halted: () -> Boolean = { false },
) : UsageRecorderCore.Transport {
    /** The ledger could not be fetched or stored. The recorder swallows it: usage is a ranking hint. */
    class Unavailable(what: String) : Exception(what)

    override suspend fun fetchSealed(): String? {
        if (halted()) throw Unavailable("halted")
        val r = client.call(WireRoute.USAGE_GET, decode = { WireJson.json.decodeFromString(UsageResponse.serializer(), it) })
        return (r as? WireResult.Ok)?.value?.sealedUsage ?: if (r is WireResult.Ok) null else throw Unavailable("fetch")
    }

    override fun open(sealed: String): ByteArray = withUsageKey { Envelope.openB64(crypto, it, sealed, Ad.usage(userId)) }

    override fun seal(plain: ByteArray): String = withUsageKey { Envelope.sealB64(crypto, it, plain, Ad.usage(userId)) }

    override suspend fun put(sealed: String) {
        if (halted()) throw Unavailable("halted")
        // Sealed before a wait, sent after it: not once the account's keys are gone.
        if (!keys.keysLive) throw Unavailable("locked")
        val body = WireJson.json.encodeToString(UsagePut.serializer(), UsagePut(sealed))
        if (client.call(WireRoute.USAGE_PUT, bodyJson = body, decode = { }) !is WireResult.Ok) throw Unavailable("store")
    }

    private fun <T> withUsageKey(block: (ByteArray) -> T): T {
        val personal = keys.personalVaultId ?: throw CryptoException("no personal vault: the usage ledger is paused")
        // The key is lent under the account's guard and the usage key derived inside it.
        return keys.withKey(personal) { vk ->
            val usageKey = UsageKey.usageKey(crypto, vk)
            try {
                block(usageKey)
            } finally {
                usageKey.fill(0)
            }
        } ?: throw CryptoException("no personal vault key")
    }
}
