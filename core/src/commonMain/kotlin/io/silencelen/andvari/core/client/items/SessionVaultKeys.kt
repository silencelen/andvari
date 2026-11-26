package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.log.VaultLogEngine
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.log.VerifiedVaultState
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * The rows the vault-log engine asks the item plane for (the item half of
 * [io.silencelen.andvari.core.client.log.VaultLogHost]): this account's own grant row of a vault, a vault's name under a
 * key the log engine is checking, and the metadata of a vault it is creating. [SessionVaultKeys] keeps it current from
 * what [ItemEngine] reports; a host builds its `VaultLogHost` from this and its contact book.
 */
class VaultRows(crypto: CryptoProvider) {
    private val codec = ItemCodec(crypto)
    private val grants = HashMap<String, SyncGrant>()
    private val vaults = HashMap<String, SyncVault>()

    fun grantRow(vaultId: String): SyncGrant? = grants[vaultId]
    fun vaultRow(vaultId: String): SyncVault? = vaults[vaultId]
    fun vaultName(vaultId: String, vk: ByteArray): String? = vaults[vaultId]?.let { codec.vaultName(vk, vaultId, it.metaBlob) }
    fun sealMeta(vaultId: String, vk: ByteArray, name: String): String = codec.sealVaultMeta(vk, vaultId, name)

    internal fun vaultIds(): Set<String> = vaults.keys.toSet()

    internal fun put(newVaults: List<SyncVault>, newGrants: List<SyncGrant>, replace: Boolean) {
        if (replace) {
            vaults.clear()
            grants.clear()
        }
        for (v in newVaults) vaults[v.vaultId] = v
        for (g in newGrants) grants[g.vaultId] = g
    }
}

/**
 * [VaultKeySource] for a signed-in, unlocked account: the personal vault from the [OpenedAccount] (design §5.3) and
 * every shared vault from the vault-log engine's adopted keys and statuses (design §3.6, §3.9). It opens nothing
 * itself: it tells [logs] what sync showed ([VaultLogEngine.refresh], [VaultLogEngine.noteItemHead]), asks it to run
 * its adoption rules, and reads the outcome.
 *
 * [state] is device state (it outlives the offline cache): the vaults the server said this account lost while the
 * log shows no reason, which stay [VaultStanding.WITHHELD] until the server serves a grant for them again.
 *
 * **Which adoption runs.** [reopen] (a cold start from the cache) reads this device's own state only, so it asks
 * [VaultLogEngine.reopenAdopted]: nothing is sent, no self-wrap is posted, no vault record is written. [served] asks the
 * online [VaultLogEngine.adoption], unless [mayDial] says the origin may not be dialed now (its pin forked, damaged or
 * moving): then it too reopens adopted keys only.
 */
class SessionVaultKeys(
    private val account: OpenedAccount,
    private val logs: VaultLogEngine,
    private val rows: VaultRows,
    private val state: DeviceState,
    private val mayDial: () -> Boolean = { true },
) : VaultKeySource {
    private val me: String get() = account.userId
    private val lostKey = "ovh.items|${account.userId}|lost"

    /**
     * The vault the account genesis names. It is the personal vault whether or not its wrap opened: with the wrap
     * withheld it is simply absent, and it is never handed to the log engine as if it were a shared vault.
     */
    private val genesisVault: String = account.genesis.fields.personalVaultId

    override val personalVaultId: String? get() = account.personalVaultId

    private fun claimedLost(): Set<String> = state.get(lostKey)?.split(',')?.filterTo(HashSet()) { it.isNotEmpty() } ?: emptySet()
    private fun setClaimedLost(ids: Set<String>) = state.set(lostKey, ids.sorted().joinToString(",").ifEmpty { null })

    override val keysLive: Boolean get() = !account.isWiped

    override fun access(vaultId: String): VaultAccess? {
        // A wiped account's vaults are neither "verified, owner" nor absent: it answers nothing.
        account.guard.check()
        if (vaultId == genesisVault) {
            return if (account.personalVk != null) VaultAccess(vaultId, true, VaultAccess.ROLE_OWNER, VaultStanding.VERIFIED) else null
        }
        // A key the vault-log engine did not adopt is never used (design §3.6): a key held for copying out of a vault whose
        // log names this account a member again gives no access (the add is still to be answered).
        if (!logs.adoptionSettled(vaultId)) return null
        return when (val st = logs.status(vaultId)) {
            is VaultLogStatus.Verified ->
                if (st.state.deletedId != null) null
                else member(st.state, if (vaultId in claimedLost()) VaultStanding.WITHHELD else VaultStanding.VERIFIED)
            is VaultLogStatus.Withheld -> member(st.state, VaultStanding.WITHHELD)
            is VaultLogStatus.Frozen -> member(st.state, VaultStanding.FROZEN)
            is VaultLogStatus.Failed -> st.lastGood?.let { member(it, VaultStanding.FAILED) }
            is VaultLogStatus.Purged, is VaultLogStatus.Removed, is VaultLogStatus.Unknown -> null
        }
    }

    private fun member(s: VerifiedVaultState, standing: VaultStanding): VaultAccess? =
        s.members[me]?.let { VaultAccess(s.vaultId, false, it.role, standing) }

    override fun <T> withKey(vaultId: String, block: (ByteArray) -> T): T? {
        account.guard.check()
        return if (vaultId == genesisVault) account.personalVk?.use(block) else logs.withKey(vaultId, block)
    }

    override fun departure(vaultId: String): VaultDeparture? {
        account.guard.check()
        if (vaultId == genesisVault) return null
        return when (val st = logs.status(vaultId)) {
            is VaultLogStatus.Removed -> if (st.byOwner) VaultDeparture.REMOVED else VaultDeparture.LEFT
            is VaultLogStatus.Purged -> VaultDeparture.PURGED
            is VaultLogStatus.Verified -> if (st.state.deletedId != null) VaultDeparture.DELETED else null
            else -> null
        }
    }

    override fun heldClosedAsMemberAgain(vaultId: String): Boolean {
        account.guard.check()
        return vaultId != genesisVault && logs.heldWhileMemberAgain(vaultId)
    }

    override fun logHead(vaultId: String): LogHeadStamp? {
        if (vaultId == genesisVault) return null
        val st = logs.status(vaultId) as? VaultLogStatus.Verified ?: return null
        return LogHeadStamp(st.state.headSeq, st.state.headHash)
    }

    override suspend fun served(report: ServedVaults) {
        val own = report.grants.filter { it.userId == me }
        rows.put(report.vaults, own, replace = report.full)
        // A served row is a hint to fetch (design §3.9); the personal vault has no log.
        val servedNow = report.vaults.mapTo(HashSet()) { it.vaultId }
        // The round's counter reaches the log engine before its first refresh, so a round whose counter equals the
        // one held here reads no account state (spec 03 §4 `accountStateSeq`); without one, every round reads as before.
        logs.accountStateServed(report.accountStateSeq)
        for (v in report.vaults) if (v.vaultId != genesisVault) logs.refresh(v.vaultId, v.logHead?.seq, v.logHead?.hash)
        // Every sync also lets the log engine look again at the vaults this pull did not mention, against the head the
        // server last served for each (design §3.9: a withheld or failed vault is re-checked at every sync, also when
        // the served head equals its own; a vault in order answers from its own state without a fetch).
        for (id in rows.vaultIds()) {
            if (id == genesisVault || id in servedNow || id in report.lostAccess) continue
            val head = rows.vaultRow(id)?.logHead
            logs.refresh(id, head?.seq, head?.hash)
        }
        val lost = claimedLost().toMutableSet()
        lost -= own.mapTo(HashSet()) { it.vaultId }
        for (id in report.lostAccess) {
            if (id == genesisVault || !TrustGrammar.isUuid(id)) continue
            // What this device believes about a lost grant comes from the log, which the server still serves up to
            // the entry that ended this account's access (spec 03 §10.6); the served row is only the cue to look.
            if (logs.status(id) !is VaultLogStatus.Unknown) logs.refresh(id, null, null, force = true)
            if (departure(id) == null) lost += id else lost -= id
        }
        setClaimedLost(lost)
        adopt(online = mayDial())
    }

    override suspend fun reopen(vaults: List<SyncVault>, grants: List<SyncGrant>) {
        rows.put(vaults, grants.filter { it.userId == me }, replace = true)
        adopt(online = false)
    }

    /**
     * Run the log engine's adoption rules for every shared vault it holds no key for yet; its verdict is its own.
     * [online] false reopens only what this device already adopted ([VaultLogEngine.reopenAdopted]).
     */
    private suspend fun adopt(online: Boolean) {
        for (id in rows.vaultIds()) {
            if (id == genesisVault || logs.adoptionSettled(id)) continue
            if (logs.status(id) is VaultLogStatus.Unknown) continue
            if (online) logs.adoption(id) else logs.reopenAdopted(id)
        }
    }

    override suspend fun itemHead(vaultId: String, seq: Long, hash: String) {
        if (vaultId != genesisVault) logs.noteItemHead(vaultId, seq, hash)
    }
}
