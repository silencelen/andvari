package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.FillCard
import io.silencelen.andvari.core.app.FillCredential
import io.silencelen.andvari.core.app.FillLogin
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.OriginCanon
import io.silencelen.andvari.core.client.VaultItem
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.trust.TrustGrammar
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * One item of the fill snapshot: only what a fill needs. A login keeps its name, username, password, addresses and
 * one-time code secret; a card its name and card fields. Notes, password history, files and their keys, and every
 * other kind of item are never in it.
 */
@Serializable
internal class FillSnapshotItem(val itemId: String, val vaultId: String, val rev: Long, val updatedAt: Long, val doc: ItemDoc)

/**
 * What the iPhone's AutoFill extension and the Safari extension's native handler read instead of the vault (design
 * 2026-11-09 "AutoFill", 2026-11-15 "Vaults left out of the AutoFill snapshot and the extension"), on the new session:
 * the logins and cards of the app's working set, exactly as the app offers them. A vault not accepted, frozen or failed
 * is never in it, and one that freezes later leaves it at the next write.
 *
 * Version 3. The whole snapshot is sealed under the account's vault key ([OpenedAccount.sealUnderVaultKey], purpose
 * [PURPOSE]): a key derived from the UVK for this purpose, with associated data naming the account, so a snapshot for
 * one account, purpose or key never opens as another's, and nothing in it (not even which vaults or items there are)
 * can be read or changed without the UVK. The app trusts nothing of it: it only writes it. Older versions (1: the old
 * account's keys and grants; 2: UVK wraps and the server's rows) are not read.
 */
@Serializable
internal class ContentFillSnapshot(
    val v: Int = VERSION,
    /** The canonical origin this account lives at; a reader that dials another origin does not use it. */
    val origin: String,
    val userId: String,
    val items: List<FillSnapshotItem>,
    val writtenAtMs: Long,
) {
    fun encode(): ByteArray = json.encodeToString(serializer(), this).encodeToByteArray()

    companion object {
        const val VERSION = 3

        /** The seal purpose of the snapshot ([OpenedAccount.sealUnderVaultKey]). */
        const val PURPOSE = "fill-snapshot"

        private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

        /** Null for anything that is not a snapshot of this version. */
        fun decode(bytes: ByteArray): ContentFillSnapshot? =
            runCatching { json.decodeFromString(serializer(), bytes.decodeToString()) }.getOrNull()?.takeIf { it.v == VERSION }

        /** What of [item] goes into the snapshot; null for an item that is not filled (a note, or anything else). */
        fun fillable(item: VaultItem): FillSnapshotItem? {
            val d = item.doc
            val doc = when {
                d.type == "login" && d.login != null -> d.login.let { l ->
                    // Only the addresses a fill reads ([FillRules.MAX_FILL_ADDRESSES]), as the app's own fill reads them.
                    ItemDoc(type = "login", name = d.name, login = LoginData(username = l.username, password = l.password, uris = FillRules.addresses(l), totp = l.totp))
                }
                d.type == "card" && d.card != null -> ItemDoc(type = "card", name = d.name, card = d.card.copy(extras = emptyMap()))
                else -> return null
            }
            return FillSnapshotItem(item.itemId, item.vaultId, item.rev, item.updatedAt, doc)
        }
    }
}

/**
 * Writes the snapshot into the App Group store [store], sealed by [account]. Only the app writes it, and never reads it.
 *
 * - Something to offer: written in place of what was there. A write the store refuses, or a seal that fails for any
 *   reason but a lock, deletes what was there: an older snapshot could still hold a vault that has since frozen.
 * - Nothing to offer (the policy forbids keeping data here, or no login or card is in the working set): deleted.
 * - The account locked meanwhile (its keys wiped): nothing is written or deleted; the next unlock writes again.
 */
internal class FillSnapshotWriter(private val store: FillSnapshotStore, private val account: OpenedAccount, private val crypto: CryptoProvider) {
    fun write(snapshot: ContentFillSnapshot?) {
        if (snapshot == null) {
            runCatching { store.delete() }
            return
        }
        val plain = snapshot.encode()
        val sealed = try {
            account.sealUnderVaultKey(crypto, ContentFillSnapshot.PURPOSE, plain)
        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
            return
        } catch (c: CancellationException) {
            throw c
        } catch (e: Exception) {
            runCatching { store.delete() }
            return
        } finally {
            plain.fill(0)
        }
        val written = runCatching { store.write(sealed) }.getOrDefault(false)
        if (!written) runCatching { store.delete() }
    }

    fun delete() {
        runCatching { store.delete() }
    }
}

/**
 * How the extension opens the sealed snapshot: the opening twin of [OpenedAccount.sealUnderVaultKey] for the signed-in
 * account, over the UVK the extension's own quick unlock released. The extension holds no identity key, so it cannot
 * open an [OpenedAccount]: the engine's opener that works from the UVK alone is what goes here (in tests,
 * [OpenedAccount.openUnderVaultKey] itself). Answers the plain bytes, or null for a seal of another account, purpose or
 * key, or a damaged one; it may throw (a key already wiped). Either way the snapshot is unknown, never empty.
 */
fun interface FillSnapshotOpener {
    @Throws(Exception::class)
    fun openUnderVaultKey(purpose: String, bytes: ByteArray): ByteArray?
}

/** What reading the snapshot came to in the extension. */
sealed class FillSnapshotRead {
    /** The snapshot opened for this account at this origin: [vault] answers as the app does. */
    class Opened internal constructor(val vault: FillSnapshotVault) : FillSnapshotRead()

    /**
     * No snapshot is kept: the app has none to offer here (signed out, the policy forbids keeping data on this device,
     * no login or card to fill, or it has not written one yet). The extension asks the person to open the app.
     */
    object Absent : FillSnapshotRead()

    /**
     * A snapshot may be there, but it could not be read or opened: the storage failed, or it is another account's,
     * another origin's, another key's, damaged, or of another version. Unknown, never "nothing to fill": the extension
     * asks the person to open the app and says nothing about what is saved.
     */
    object Unreadable : FillSnapshotRead()
}

/**
 * The extension's read-only vault over the snapshot: never a network call, never the password KDF, never a token. The
 * items are held in memory until [close]. The answers are the app's own ([FillRules]).
 *
 * What it does not do, because the extension's host does it first: release the UVK (Face ID over the quick-unlock
 * blob), apply the quick-unlock gates (policy, biometric, enrolment, expiry) and their sentences, and read the stored
 * session's identity (origin and user) to hand to [read].
 */
class FillSnapshotVault private constructor(private var items: List<VaultItem>, private val crypto: CryptoProvider) {
    private val byId get() = items.associateBy { it.itemId }

    /** The logins, those matching one of [hosts] (domains or URLs) first. Empty once closed. */
    fun logins(hosts: List<String>): List<FillLogin> = FillRules.logins(items, hosts)

    /** Whether [itemId] is a login for one of [identifiers]: asked before a suggestion's record is filled. */
    fun matches(itemId: String, identifiers: List<String>): Boolean = FillRules.matches(byId[itemId], identifiers)

    fun credential(itemId: String): FillCredential? = FillRules.credential(byId[itemId])

    fun cards(): List<FillCard> = FillRules.cards(items)

    fun cardField(itemId: String, field: String): String? = FillRules.cardField(byId[itemId], field)

    /** The current one-time code of [itemId] at [nowMs]; null when it has none. */
    fun oneTimeCode(itemId: String, nowMs: Long): String? = runCatching {
        val uri = byId[itemId]?.doc?.login?.totp?.ifEmpty { null } ?: return null
        Totp.code(crypto, Totp.parseUri(Totp.normalize(uri)), nowMs / 1000)
    }.getOrNull()

    /** End the fill: the items are let go. Idempotent. */
    fun close() {
        items = emptyList()
    }

    companion object {
        /**
         * Read the App Group [store] for [userId] at [origin] (the stored session's, never the snapshot's own word),
         * opened with [opener]. [FillSnapshotRead.Absent] only when the store says no snapshot is there; a store that
         * fails, or a snapshot that does not open as this account's at this origin, is [FillSnapshotRead.Unreadable].
         */
        fun read(crypto: CryptoProvider, store: FillSnapshotStore, origin: String, userId: String, opener: FillSnapshotOpener): FillSnapshotRead {
            val bytes = try {
                store.readStrict() ?: return FillSnapshotRead.Absent
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                return FillSnapshotRead.Unreadable
            }
            return readBytes(crypto, bytes, origin, userId, opener)
        }

        /** [read] over bytes already read: [FillSnapshotRead.Opened] or [FillSnapshotRead.Unreadable], never absent. */
        fun readBytes(crypto: CryptoProvider, bytes: ByteArray, origin: String, userId: String, opener: FillSnapshotOpener): FillSnapshotRead {
            val plain = try {
                opener.openUnderVaultKey(ContentFillSnapshot.PURPOSE, bytes)
            } catch (c: CancellationException) {
                throw c
            } catch (e: Exception) {
                null
            } ?: return FillSnapshotRead.Unreadable
            val snap = try {
                ContentFillSnapshot.decode(plain)
            } finally {
                plain.fill(0)
            } ?: return FillSnapshotRead.Unreadable
            val sameOrigin = runCatching { OriginCanon.originKey(snap.origin) == OriginCanon.originKey(origin) }.getOrDefault(false)
            if (!sameOrigin || snap.userId != userId) return FillSnapshotRead.Unreadable
            val seen = HashSet<String>()
            val items = snap.items.mapNotNull { i ->
                if (!TrustGrammar.isUuid(i.itemId) || !TrustGrammar.isUuid(i.vaultId) || !seen.add(i.itemId)) return@mapNotNull null
                if (i.doc.type != "login" && i.doc.type != "card") return@mapNotNull null
                VaultItem(i.itemId, i.vaultId, i.rev, i.updatedAt, i.doc)
            }
            return FillSnapshotRead.Opened(FillSnapshotVault(items, crypto))
        }
    }
}
