package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.BlobStore
import io.silencelen.andvari.core.app.FillSnapshotStore
import io.silencelen.andvari.core.app.SaveQueueStore
import io.silencelen.andvari.core.client.AccountWipedException
import io.silencelen.andvari.core.client.items.CopyDeletion
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KeysGoneException
import kotlinx.coroutines.CancellationException

/**
 * What the vault's content keeps on this device across a lock, and where (the host's app-private storage). Every
 * record is sealed to the signed-in account with a MAC only it can make ([OpenedAccount.sealLocalRecord]), under the
 * purpose strings the old controller used, so a record the old app kept opens here and the other way round:
 *  - [moves]: moves and copies that did not finish ("move-memos"), so Try again after an unlock replays the same ids;
 *  - [keptSaves]: saves with new files a lock cut short ("kept-saves"), finished after the next unlock;
 *  - [files]: the new files those saves name, each encrypted under its own key (never a decrypted file);
 *  - [applied]: the list of automatic saves from the extensions' queue ("applied-saves");
 *  - [queue]: the extensions' save queue (the App Group on iOS, the autofill service's storage on Android), or
 *    [SaveQueueStore.None] on a host with no extension that saves;
 *  - [fill]: where the iPhone's AutoFill snapshot is written (the App Group), sealed under the account's vault key
 *    ([ContentFillSnapshot]); [FillSnapshotStore.None] on a host with no extension that reads one. The content writes
 *    it at unlock, after every completed sync and after each of the person's writes, and deletes it when there is
 *    nothing to offer; [dropAll] and [ContentStores.drop] delete it with the rest.
 *
 * The host makes one per unlock, with that unlock's [account], and keeps the stores themselves across locks: a store
 * kept only in memory (the policy forbids keeping data on this device, `offlineCacheAllowed` false) must outlive the
 * content instance, or a save a lock cut short is lost with it.
 *
 * A locked account is not an unreadable record: once [account] is wiped, nothing is read, written or removed here.
 */
class ContentKeeping(
    val account: OpenedAccount,
    val moves: FillSnapshotStore,
    val keptSaves: FillSnapshotStore,
    val files: BlobStore,
    val applied: FillSnapshotStore,
    val queue: SaveQueueStore,
    val fill: FillSnapshotStore = FillSnapshotStore.None,
    /** Changes a lock overtook before they were kept, for the next unlock to say; in this process's memory only. */
    val unsaved: UnsavedAtLock = UnsavedAtLock(),
) {
    /**
     * The person's own act ([why]: sign-out, "Forget this server", account deletion, a policy that forbids an offline
     * copy): every kept record, every file set aside, the queue and its published key go. Needs no key, so it works
     * while locked. Never for a session the server ended (design §4.4): [CopyDeletion] has no value for it.
     */
    @Suppress("UNUSED_PARAMETER")
    fun dropAll(why: CopyDeletion) {
        runCatching { moves.delete() }
        runCatching { keptSaves.delete() }
        runCatching { files.clear() }
        runCatching { applied.delete() }
        // Logins the phone caught stay through a policy's wipe until the person answers them (decided on 2026-11-18).
        if (why != CopyDeletion.POLICY_FORBIDS_OFFLINE_COPY) runCatching { queue.clear() }
        runCatching { fill.delete() }
    }
}

/**
 * What reading a kept record came to. A record that cannot be read is unknown, never empty:
 * on [Unreadable] and on [Locked] nothing is replaced, removed or swept, and the operation that needed the record
 * stops; a later read that succeeds finds everything as it was.
 */
internal sealed interface KeptRead<out T> {
    class Read<T>(val value: T) : KeptRead<T>

    /** The account is locked (its keys wiped): nothing can be told about the record now. */
    object Locked : KeptRead<Nothing>

    /** The record could not be read: the host's storage failed, or opening it failed for a reason other than a seal. */
    object Unreadable : KeptRead<Nothing>
}

/**
 * The host's record, or null when there is none; [KeptRead.Unreadable] when reading it failed. A host's store answers
 * null only for a record that is not there and throws when one could not be read; a store that swallows a failure in
 * [FillSnapshotStore.read] for its old callers says so through [StrictRecordStore], which is read instead.
 */
internal fun FillSnapshotStore.readKept(): KeptRead<ByteArray?> = try {
    KeptRead.Read(readStrict())
} catch (c: CancellationException) {
    throw c
} catch (e: Exception) {
    KeptRead.Unreadable
}

/** What opening a kept record came to. */
internal sealed interface Unsealed {
    /** This account sealed it for this purpose: the plaintext, which the caller zeroes. */
    class Plain(val bytes: ByteArray) : Unsealed

    /** Not this account's record for this purpose (another account's, another purpose's, a forgery, damaged). */
    object NotOurs : Unsealed

    /** The account is locked (its keys wiped): nothing can be told about the record now, and it stays as it is. */
    object Locked : Unsealed

    /** Opening it failed for a reason that says nothing about the record (not a seal or a MAC that does not hold). */
    object Failed : Unsealed
}

/**
 * The account's local-record seals for the content, with a lock told apart from a record that is not ours
 * ([AccountWipedException] from the account is [Unsealed.Locked], never [Unsealed.NotOurs]).
 */
internal class LocalRecords(private val account: OpenedAccount, private val crypto: CryptoProvider) {
    /** [plain] sealed for [purpose]; null when the account is locked (nothing may be written then). */
    fun seal(purpose: String, plain: ByteArray): ByteArray? = try {
        account.sealLocalRecord(crypto, purpose, plain)
    } catch (e: KeysGoneException) {
        null
    }

    fun open(purpose: String, record: ByteArray): Unsealed = try {
        account.openLocalRecord(crypto, purpose, record)?.let { Unsealed.Plain(it) } ?: Unsealed.NotOurs
    } catch (e: KeysGoneException) {
        Unsealed.Locked
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        // The account answers null for a record that is not ours; a throw is a failure, which says nothing about it.
        Unsealed.Failed
    }

    /**
     * A sealed box to the identity key alone: an entry of the extensions' save queue, and nothing else.
     * Only a box that does not open ([CryptoException], or bytes that are no box at all) is [Unsealed.NotOurs], which
     * removes the entry; any other failure says nothing about the entry and is [Unsealed.Failed], which keeps the queue
     * as it is.
     */
    fun openQueued(sealed: ByteArray): Unsealed = try {
        Unsealed.Plain(account.openQueuedSave(crypto, sealed))
    } catch (e: KeysGoneException) {
        Unsealed.Locked
    } catch (e: CryptoException) {
        Unsealed.NotOurs
    } catch (e: IllegalArgumentException) {
        Unsealed.NotOurs
    } catch (c: CancellationException) {
        throw c
    } catch (e: Exception) {
        Unsealed.Failed
    }

    /** The public key a save is sealed to; readable while locked too. */
    fun identityPub(): ByteArray = account.identityPub()

    val userId: String get() = account.userId
    val personalVaultId: String? get() = account.personalVaultId

    companion object {
        /** The purposes, the old controller's word for word ([OpenedAccount.sealLocalRecord]). */
        const val MOVES = "move-memos"
        const val KEPT_SAVES = "kept-saves"
        const val APPLIED_SAVES = "applied-saves"
    }
}
