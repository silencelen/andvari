package io.silencelen.andvari.cli

import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.ItemDocShape
import io.silencelen.andvari.core.client.items.ItemCodec
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.client.items.ItemFailure
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.PinnedOriginGate
import io.silencelen.andvari.core.client.items.SavedItem
import io.silencelen.andvari.core.client.items.SessionVaultKeys
import io.silencelen.andvari.core.client.items.VaultRows
import io.silencelen.andvari.core.client.items.WireItemTransport
import io.silencelen.andvari.core.client.items.Written
import io.silencelen.andvari.core.client.link.AccountContactBook
import io.silencelen.andvari.core.client.link.ContactCurrency
import io.silencelen.andvari.core.client.link.LinkAccount
import io.silencelen.andvari.core.client.log.StoredVaultLogs
import io.silencelen.andvari.core.client.log.VaultLogHost
import io.silencelen.andvari.core.client.onboard.SessionHow
import io.silencelen.andvari.core.model.wire.SyncGrant
import io.silencelen.andvari.core.model.wire.SyncVault
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/** One decrypted item: its id, vault, server rev and the plaintext document (spec 02 §3). */
data class PlainItem(val itemId: String, val vaultId: String, val rev: Long, val formatVersion: Int, val doc: JsonObject)

/** What a sync came to. */
sealed class SyncOutcome {
    data class Synced(val rev: Long) : SyncOutcome()
    data class Refused(val code: String) : SyncOutcome()
    data object Unreachable : SyncOutcome()
}

/**
 * The signed-in account on this host: account state, contacts, the vault-log engine and the item engine of `:core`
 * ([ItemEngine]) over `/sync`, `/sync/push`, the item and attachment routes (spec 03 §4, §5, §9). The vault-log engine
 * decides every key; [vaultKeys] hands the item engine only what it adopted (design §3.6) and the account's own
 * personal vault key, and [items] moves ciphertext and decrypts under those.
 */
class AccountSession(val host: Host, val held: HeldSession) {
    val origin: String get() = held.origin
    val userId: String get() = held.userId
    private val crypto get() = host.crypto
    val client get() = host.client(origin)
    val store = host.accountState(held)
    /** The name is read each time: the CLI learns it at registration, after the session opened. */
    val link: LinkAccount get() = LinkAccount.of(held.session, host.displayName(origin, userId), store)
    val currency = ContactCurrency(host.state, crypto, origin, userId)
    val contacts get() = AccountContactBook(link, currency, passwordOnly = held.session.how == SessionHow.PASSWORD, clock = host.clock)

    /** The grant and vault rows of the last sync: the item plane's half of what the vault-log engine asks its host. */
    private val rows = VaultRows(crypto)

    private val logHost = object : VaultLogHost {
        override fun grantRow(vaultId: String): SyncGrant? = rows.grantRow(vaultId)
        override fun isCurrentContact(userId: String, identityPub: String): Boolean = contacts.currentFor(userId, identityPub) != null
        override fun currentContact(userId: String): Pair<String, Boolean>? {
            val r = store.local().contacts[userId] ?: return null
            return if (contacts.currentFor(userId, r.identityPub) != null) r.identityPub to r.compared else null
        }
        override fun labelFor(userId: String, identityPub: String): String? = contacts.currentFor(userId, identityPub)?.labelText
        override fun vaultName(vaultId: String, vk: ByteArray): String? = rows.vaultName(vaultId, vk)
        override fun sealMeta(vaultId: String, vk: ByteArray, name: String): String = rows.sealMeta(vaultId, vk, name)
        override fun serverOwnerName(vaultId: String): String? = null
    }

    val logs = StoredVaultLogs.forAccount(
        held.session.account, client, crypto, host.state, store, logHost,
        host.clock, { vaultId -> io.silencelen.andvari.core.client.devicelink.BundleCheckpoints(host.state).get(origin, userId, vaultId) },
    )

    /** Which vaults this account may read and write now: the personal vault, and what [logs] adopted. */
    val vaultKeys = SessionVaultKeys(held.session.account, logs, rows, host.state)

    /** The origin's pin, as the item engine asks about it: every sync judges the card chain first (design §4.4). */
    val gate = PinnedOriginGate(host.trust, origin)

    /**
     * The item engine on this session; its cache lives in this origin's and this account's namespace. Attachments go
     * over the session's own guarded client ([io.silencelen.andvari.core.client.items.WireAttachments]).
     */
    val items = ItemEngine(WireItemTransport(client), vaultKeys, gate, host.itemCache(held), userId, crypto, host.clock)

    private var hydrated = false
    private var stateRead = false

    /**
     * The served account state, read once per session: merged into this
     * device's copy, so what another device of the account decided (a contact compared, a share accepted) is known here
     * as it is to the apps, which read it once per opening. [sync] calls it before its first cycle, and so does every
     * command that shows what the account state holds. A read that does not open or is stopped is said; the device's own
     * copy stays in force (the shared code never adopts what it cannot read). No answer is left to the command's own call.
     * Nothing is read when the shared gate halts on the served card chain: the command's own call then stops on it.
     */
    suspend fun readAccountStateOnce() {
        if (stateRead) return
        stateRead = true
        // The served card chain is judged first, by the shared gate the sync itself asks (design §4.4): an instance whose
        // chain forked, or whose pin is not in force, is sent nothing, not even this read (the hostile bench's H1).
        if (gate.judge()) return
        when (val r = store.read()) {
            is io.silencelen.andvari.core.client.state.AccountStateRead.Ok, io.silencelen.andvari.core.client.state.AccountStateRead.Unreachable -> {}
            io.silencelen.andvari.core.client.state.AccountStateRead.Unopenable ->
                Term.note("andvari-cli: note: the account's state on $origin did not open on this device; this device's own copy stays in force")
            is io.silencelen.andvari.core.client.state.AccountStateRead.Stopped ->
                Term.note("andvari-cli: note: the account's state on $origin was not read (${r.code}); this device's own copy stays in force")
        }
    }

    val personalVaultId: String? get() = held.session.account.personalVaultId

    /**
     * Account deletion with its leaves (design §3.11). Each leave is placed from the verified state of this session's
     * own log engine ([logs]), which answers nothing for a vault any of whose trust records cannot be read; the
     * deletion then treats that vault's served head as unverified (the one-day bound of FS-R7).
     */
    fun deletion(onDeleted: suspend () -> Unit) = io.silencelen.andvari.core.client.deletion.WireAccountDeletion(
        held.session.account, held.emailNorm, client, crypto, host.reauth(held), logs, host.clock, onDeleted,
    )

    /**
     * One sync cycle of the item engine: queued writes pushed, the delta pulled, every shared vault's log fetched and
     * verified where its served head moved. The first call rebuilds the working set from the cache.
     */
    suspend fun sync(): SyncOutcome {
        readAccountStateOnce()
        if (!hydrated) {
            items.hydrate()
            hydrated = true
        }
        return when (val r = items.sync()) {
            is ItemResult.Ok -> SyncOutcome.Synced(r.value.rev)
            is ItemResult.Failed -> when (val why = r.why) {
                is ItemFailure.Unreachable -> SyncOutcome.Unreachable
                else -> SyncOutcome.Refused(code(why))
            }
        }
    }

    /** Every vault the server listed for this account, readable here or not. */
    fun vaultIds(): List<String> = items.vaultRows().map { it.vaultId }.sorted()
    fun vault(vaultId: String): SyncVault? = rows.vaultRow(vaultId)
    fun grant(vaultId: String): SyncGrant? = rows.grantRow(vaultId)

    /** The vault's name, when this device may read it. */
    fun vaultName(vaultId: String): String? = items.vaults().firstOrNull { it.vaultId == vaultId }?.name

    /** The live items of [vaultId] this device can open, queued writes included. */
    fun items(vaultId: String): List<PlainItem> = items.items().filter { it.vaultId == vaultId }.sortedBy { it.itemId }.map {
        PlainItem(it.itemId, it.vaultId, it.rev, ItemCodec.docFloor(it.doc), json.encodeToJsonElement(ItemDoc.serializer(), it.doc).jsonObject)
    }

    /** True when an item write under [vaultId] is allowed: the personal vault, or a shared vault whose log verified (design §3.6). */
    fun writeAllowed(vaultId: String): Boolean = vaultKeys.access(vaultId)?.writable == true

    /**
     * Put [doc] as [itemId] (a new id when null) into [vaultId]; an existing item is edited in place. Answers what was
     * saved, or a refusal code.
     */
    suspend fun putItem(vaultId: String, doc: JsonObject, itemId: String? = null): Pair<SavedItem?, String?> {
        if (itemId != null && !TrustGrammar.isUuid(itemId)) return null to "bad_item_id"
        val parsed = parse(doc) ?: return null to "bad_item"
        val r = if (itemId != null && items.item(itemId) != null) items.save(itemId, parsed, vaultId) else items.save(null, parsed, vaultId, draftItemId = itemId)
        return when (r) {
            is ItemResult.Ok -> r.value to null
            is ItemResult.Failed -> null to code(r.why)
        }
    }

    /** The account's own meters as the freshest completed pull served them (null: the server gave none, or none that are meters). */
    fun quota(): io.silencelen.andvari.core.model.wire.QuotaUse? = items.quota()?.takeIf { it.isWhole() }

    suspend fun deleteItem(itemId: String): Pair<Written?, String?> {
        if (items.item(itemId) == null) return null to "unknown_item"
        return when (val r = items.remove(itemId)) {
            is ItemResult.Ok -> r.value to null
            is ItemResult.Failed -> null to code(r.why)
        }
    }

    private fun parse(doc: JsonObject): ItemDoc? {
        if (ItemDocShape.problem(doc) != null) return null
        return runCatching { json.decodeFromJsonElement(ItemDoc.serializer(), doc) }.getOrNull()
    }

    companion object {
        private val json = Json { ignoreUnknownKeys = true }

        /** One word for a failure, as the CLI prints it. */
        fun code(why: ItemFailure): String = when (why) {
            is ItemFailure.Unreachable -> "unreachable"
            is ItemFailure.Refused -> why.code
            is ItemFailure.Rollback -> "rev_regression"
            ItemFailure.Halted -> "halted"
            is ItemFailure.NotAllowed -> why.reason.name.lowercase()
            is ItemFailure.Denied -> "denied"
            is ItemFailure.Corrupt -> "attachment_${why.what}"
        }
    }
}
