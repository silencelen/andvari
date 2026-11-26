package io.silencelen.andvari.core.app.content

import io.silencelen.andvari.core.app.AttachmentLimitsView
import io.silencelen.andvari.core.client.items.ItemEngine
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams

/**
 * [VaultContent] over the item engine of the new session. The app API makes one per unlock, from the engine it
 * composed for that session (`ItemEngine(WireItemTransport(...), SessionVaultKeys(...), PinnedOriginGate(...), cache,
 * userId, crypto, clock)`, as the command-line tool's `AccountSession` does), and drops it on lock. The engine is the
 * host's: this class never closes it and never deletes its cache.
 */
class EngineVaultContent private constructor(private val controller: ContentController) : VaultContent by controller {
    /** Nothing is kept across a lock: an unfinished move or a save with files a lock cut short goes with this instance. */
    constructor(engine: ItemEngine, crypto: CryptoProvider, host: ContentHost) : this(ContentController(EngineContentSource(engine), crypto, host, null))

    /**
     * What a lock cuts short is kept in [keeping], sealed to its account, and finished by the next unlock's instance:
     * a move or copy that did not finish (Try again replays the same ids), a save with new files (finished after the
     * first sync).
     */
    constructor(engine: ItemEngine, crypto: CryptoProvider, host: ContentHost, keeping: ContentKeeping) :
        this(ContentController(EngineContentSource(engine), crypto, host, keeping))

    /**
     * Show what changed outside this object's own intents (the host ran a vault-log action and synced the engine
     * itself, or the engine's notices changed): a new [state] is published, and the iPhone's AutoFill snapshot is written
     * again from what the content holds now (or deleted when there is nothing to offer).
     */
    fun reload() {
        controller.writeFillSnapshot()
        controller.publish()
    }

    /** A new [state] only (the host's standing changed: the copy is being removed); nothing is written anywhere. */
    internal fun republish() = controller.publish()

    /** [ContentController.keptChangesForAttempt]. */
    internal fun keptChangesForAttempt() = controller.keptChangesForAttempt()

    /** [ContentController.settled]. */
    internal suspend fun settled() = controller.settled()
}

/** What the vault's content needs from the session that made it. Each is read when it is needed, never kept. */
interface ContentHost {
    /** The wall clock, unix milliseconds (the session's `Clocks.wallMs`): one-time codes, dates. */
    fun wallMs(): Long

    /**
     * What one file and one item's files may come to: `AttachmentRules.limits(policy.attachmentMaxBytes,
     * policy.itemAttachmentsMaxBytes)` of the client policy the session last read.
     */
    fun attachmentLimits(): AttachmentLimitsView

    /** The server's origin, as a backup records it. */
    fun origin(): String

    /** The account's user id, as a backup records it. */
    fun userId(): String

    /** "Your account ID": the identity fingerprint's short form, as a backup records it. */
    fun accountId(): String

    /** The client policy's KDF cost, for a backup's passphrase; null when no policy was read (the default is used). */
    fun backupKdfParams(): KdfParams?

    /**
     * The client policy's `offlineCacheAllowed`, as the session last read it. While it is false (and until a host says
     * otherwise: false is the default, the safer reading) the extensions' save queue is emptied and not read, no key is
     * published for it, and [VaultContent.credentialIdentities] is empty, so the host clears the system's copy.
     */
    fun offlineCacheAllowed(): Boolean = false

    /** This device's time zone: the day a line of Recently removed names to the person is named in it. */
    fun timeZone(): kotlinx.datetime.TimeZone = kotlinx.datetime.TimeZone.currentSystemDefault()

    /**
     * The name of the open invitation to [vaultId] on this device, as its prompt shows it (decrypted only after the
     * offered key matched the vault log's commitment); null where this device knows no open invitation of that vault now.
     * Read for a held copy that does not open because its person was added again and has not answered.
     */
    fun openInvitationName(vaultId: String): String? = null

    /**
     * This copy is being removed for the server's policy (its wipe is owed): nothing new is taken into it, and a change
     * the person makes is refused with [ContentCopy.COPY_BEING_REMOVED] (the item engine is halted meanwhile).
     */
    fun removingForPolicy(): Boolean = false

    /**
     * The usage ledger's store (spec 02 §8.2), for Health's "last used": the session's
     * [io.silencelen.andvari.core.client.items.SessionUsage] over its client and vault keys. Null (the default) where the
     * session has none; then nothing is ranked by use and every login says "Last used not recorded".
     */
    fun usageLedger(): io.silencelen.andvari.core.client.UsageRecorderCore.Transport? = null

    /**
     * The content recorded a use of [itemId] at [atMs] (spec 02 §8.2): it released the item's login or card to a fill
     * ([VaultContent.fillCredential], [VaultContent.fillCardField]), or the person revealed or copied one of its secrets
     * ([VaultContent.revealSecret], [VaultContent.previousPassword]). A release of the same item within a minute of the
     * last one is the same use and is not recorded again; a refused fill or a reveal that found nothing records nothing.
     *
     * The session batches and sends the ledger: `UsageRecorderCore.record(itemId, atMs)` over the same store as
     * [usageLedger], flushed by its debounce, before a lock and after a completed sync. Called on the caller's thread
     * while a secret is being handed out, so it only buffers: it must return at once and must not throw. The default
     * records nothing (a host with no ledger).
     */
    fun recordUse(itemId: String, atMs: Long) {}
}
