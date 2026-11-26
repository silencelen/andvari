package io.silencelen.andvari.core.client.session

import io.silencelen.andvari.core.client.ClientPolicyClamps
import io.silencelen.andvari.core.client.DeviceState
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.InstanceTrust
import io.silencelen.andvari.core.client.pin.PinState
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.model.wire.ClientPolicy
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.Serializable

/**
 * The platform's key for quick unlock (spec 01 §8.1): it seals a secret under a non-exportable key that only a strong
 * biometric releases, and opens it again behind the same prompt. Android: a Keystore AES-GCM key behind
 * `BIOMETRIC_STRONG`, invalidated by a new enrolment. iOS: a Secure Enclave key made with `biometryCurrentSet`.
 *
 * Core decides everything else (what is sealed, where the sealed bytes are kept, when it may be used, when it goes):
 * the platform only holds the key and shows the prompt. A device passcode never counts as a biometric here: it is
 * weaker than the master password.
 */
interface PlatformKeyWrap {
    /** A strong biometric is enrolled and usable now. */
    fun strongBiometric(): Boolean

    /**
     * The first step of enrolment: make a fresh key for [slot] (replacing any key it had), bound
     * to [aad], and ask the person's consent (the biometric prompt). No secret is handed over here: what is sealed
     * comes after the prompt, from inside the account's guarded use, through [KeyWrapPrepared.seal]. A cancelled or
     * failed prompt leaves no key behind.
     */
    suspend fun prepare(slot: String, aad: ByteArray): KeyWrapPrepare

    /** Show the prompt and open [sealed] with [aad] under [slot]'s key. */
    suspend fun open(slot: String, sealed: ByteArray, aad: ByteArray): KeyWrapOpen

    /**
     * As [open], for a confirmation of the person's presence while the vault is already open
     * ([QuickUnlockKeeper.confirmPresence]): the prompt says [reason], what the person approves (for a device link, the
     * new device's name and platform), instead of unlocking; null for the platform's own words. A platform that has
     * no prompt of its own for this shows its quick-unlock prompt ([open]): the answer is used the same way.
     */
    suspend fun openToConfirm(slot: String, sealed: ByteArray, aad: ByteArray, reason: String?): KeyWrapOpen = open(slot, sealed, aad)

    /** Destroy [slot]'s key. Idempotent; never throws. */
    fun destroy(slot: String)
}

/** What the consent step of enrolment ([PlatformKeyWrap.prepare]) came to. */
sealed class KeyWrapPrepare {
    /** The person consented: [sealer] seals once, at once. */
    class Prepared(val sealer: KeyWrapPrepared) : KeyWrapPrepare()

    /** The person cancelled the prompt: no key was kept. */
    data object Cancelled : KeyWrapPrepare()

    /** No key was kept (no usable biometric, no screen to show the prompt on, a hardware error, a lockout). */
    data object Failed : KeyWrapPrepare()
}

/**
 * What a consented prompt prepared: the second step of enrolment. Single use; it holds no secret, only what the platform
 * needs to seal (the authorised cipher, the public key) and a copy of the associated data.
 */
interface KeyWrapPrepared {
    /**
     * Seal [secret] now, synchronously: no prompt and no wait, so the caller can do it inside the account's guarded
     * use. [secret] is the guard's own lent buffer: the implementation never zeroes it and never keeps it, nor any
     * copy of it past the return. Null when it cannot be sealed now (the authorisation lapsed, the key was invalidated
     * meanwhile, it was used or discarded already): the caller then discards it and destroys the slot.
     */
    fun seal(secret: ByteArray): ByteArray?

    /** Drop what was prepared, unused. Idempotent; never throws. The slot's key is the caller's to destroy. */
    fun discard()
}

/** What one quick-unlock prompt released. */
sealed class KeyWrapOpen {
    /** The secret. The receiver owns it and wipes it. */
    class Opened(val secret: ByteArray) : KeyWrapOpen()

    /** Cancelled, or "Use master password": silent, and the key is kept. */
    data object Cancelled : KeyWrapOpen()

    /** A lockout or a sensor failure: the key is kept, and the master password is the way in now. */
    data object Refused : KeyWrapOpen()

    /** The key is gone or no longer opens (the biometrics changed, a tampered blob): a wipe-class failure. */
    data object Invalidated : KeyWrapOpen()
}

/** The client policy a server last declared, as this device keeps it per origin (spec 03 §1.1), clamped. */
class KeptPolicy internal constructor(
    /** `autoLockSeconds`, clamped into the client's range: a server can make it shorter, never longer. */
    val autoLockSeconds: Int,
    /** `clipboardClearSeconds`, clamped into `[1, CLIPBOARD_CLEAR_MAX_SECONDS]`. */
    val clipboardClearSeconds: Int,
    /** `offlineCacheAllowed`: false forbids key material at rest on this device (forbid-only). */
    val offlineCacheAllowed: Boolean,
    /** The server's own per-file ceiling (informational). */
    val attachmentMaxBytes: Long,
    /** The server's own per-item ceiling (informational). */
    val itemAttachmentsMaxBytes: Long,
    /** When this device last read it, on its wall clock. */
    val fetchedAtMs: Long,
    /**
     * `kdfParams`, the cost the server asks of a key derived from a passphrase (a backup's), only while it lies within
     * the client's sanity fence ([io.silencelen.andvari.core.client.KdfUpgrade]'s floor and ceiling): null when none was
     * read, or when the server asked for less than the floor or more than the ceiling (the default is used then).
     */
    val kdfParams: io.silencelen.andvari.core.crypto.KdfParams? = null,
)

/**
 * The policies servers declared, one per origin, in device state. Read from `GET /client-policy` through the
 * session's guarded client, so nothing is dialed at a forked or damaged origin.
 */
class KeptPolicies(private val state: DeviceState) {
    @Serializable
    private data class Stored(
        val autoLockSeconds: Int, val clipboardClearSeconds: Int, val offlineCacheAllowed: Boolean,
        val attachmentMaxBytes: Long, val itemAttachmentsMaxBytes: Long, val fetchedAtMs: Long,
        /** The policy's KDF cost; 0 in a record kept before it was kept. */
        val kdfOps: Long = 0, val kdfMemBytes: Long = 0,
    )

    fun get(origin: String): KeptPolicy? {
        val text = state.get(KEY_PREFIX + origin) ?: return null
        val s = runCatching { WireJson.json.decodeFromString(Stored.serializer(), text) }.getOrNull() ?: return null
        return KeptPolicy(s.autoLockSeconds, s.clipboardClearSeconds, s.offlineCacheAllowed, s.attachmentMaxBytes, s.itemAttachmentsMaxBytes, s.fetchedAtMs, fenced(s.kdfOps, s.kdfMemBytes))
    }

    /** The KDF cost when it lies within the client's fence (never below the floor, never above the ceiling); null otherwise. */
    private fun fenced(ops: Long, memBytes: Long): io.silencelen.andvari.core.crypto.KdfParams? {
        val k = io.silencelen.andvari.core.client.KdfUpgrade
        if (ops < k.MIN_OPS || ops > k.MAX_OPS || memBytes < k.MIN_MEM_BYTES || memBytes > k.MAX_MEM_BYTES) return null
        return io.silencelen.andvari.core.crypto.KdfParams(ops = ops, memBytes = memBytes)
    }

    /** Keep [p] for [origin], clamped, as read at [nowMs]. */
    fun record(origin: String, p: ClientPolicy, nowMs: Long): KeptPolicy {
        // What was kept before: a copy may be at rest here only under a policy that allowed one (or one that cannot be read).
        val before = get(origin)
        val couldHoldCopy = before?.offlineCacheAllowed == true || (before == null && state.get(KEY_PREFIX + origin) != null)
        val s = Stored(
            clampAutoLockSeconds(p.autoLockSeconds.coerceIn(Int.MIN_VALUE.toLong(), Int.MAX_VALUE.toLong()).toInt()),
            p.clipboardClearSeconds.coerceIn(1L, ClientPolicyClamps.CLIPBOARD_CLEAR_MAX_SECONDS.toLong()).toInt(),
            p.offlineCacheAllowed,
            p.attachmentMaxBytes.coerceAtLeast(0L),
            p.itemAttachmentsMaxBytes.coerceAtLeast(0L),
            nowMs,
            p.kdfParams.ops,
            p.kdfParams.memBytes,
        )
        state.set(KEY_PREFIX + origin, WireJson.json.encodeToString(Stored.serializer(), s))
        // On the thread that recorded it, before anything else is told: the keeper's keys at rest follow the policy now.
        // A failure there (a store that refuses the write) does not keep [onRecorded] from being told: the mark that a
        // wipe is owed is written all the same, and the failure is thrown after it (a load removes the keys left).
        val removal = runCatching { onKept?.invoke(origin) }
        val kept = get(origin)!!
        // Every road that records a policy (the opening's read, the re-key's cost read, a sign-in's) takes this one.
        onRecorded?.invoke(origin, kept, couldHoldCopy)
        removal.getOrThrow()
        return kept
    }

    /**
     * Told of every policy [record] keeps, after it is kept, with whether the policy kept before allowed a copy at rest
     * (or could not be read): where a policy now forbids the offline copy, the wipe that policy calls for is owed from
     * this moment (the app interface's mark), whichever read recorded it.
     */
    var onRecorded: ((origin: String, kept: KeptPolicy, couldHoldCopy: Boolean) -> Unit)? = null

    /**
     * Told of every policy [record] keeps, at once and on the recording thread, before [onRecorded]: under one that
     * forbids key material at rest the account's wrapped keys and the quick-unlock key leave the device then
     * ([SessionKeeper.policyRecorded]).
     */
    var onKept: ((origin: String) -> Unit)? = null

    /**
     * A record is kept for [origin] and cannot be read (damaged, or written by a format this build does not know). That
     * is not a forbidding policy: nothing is deleted on its account, and the copy stays closed until the policy is read
     * from the server again.
     */
    fun unreadable(origin: String): Boolean = state.get(KEY_PREFIX + origin) != null && get(origin) == null

    fun forget(origin: String) = state.set(KEY_PREFIX + origin, null)

    /** Read [client]'s origin's policy and keep it; null when no policy came back (nothing kept changes then). */
    suspend fun fetch(client: WireClient, nowMs: Long): KeptPolicy? =
        when (val r = client.call(WireRoute.CLIENT_POLICY, decode = { WireJson.json.decodeFromString(ClientPolicy.serializer(), it) })) {
            is WireResult.Ok -> record(client.origin, r.value, nowMs)
            else -> null
        }

    companion object {
        const val KEY_PREFIX = "ovh.policy|"
    }
}

/** Quick unlock for the kept session, as the app shows it. */
class QuickUnlockStatus internal constructor(
    /** This device has a platform key and a strong biometric enrolled. */
    val available: Boolean,
    /** The server's policy, seen within 7 days, permits key material at rest (spec 01 §8.1 A4). */
    val allowed: Boolean,
    /** A sealed key is kept for this session's account. */
    val enrolled: Boolean,
    /** Enrolled, allowed, available, and the last full-password unlock is recent enough (A1/A2): it can be used now. */
    val usable: Boolean,
    /** Offer to turn it on now (available, allowed, not enrolled, and not put off; design 2026-08-23 §7.1). */
    val offerNow: Boolean,
)

/** What turning quick unlock on came to. */
enum class QuickEnrolOutcome {
    ENROLLED,

    /** The person cancelled the prompt. */
    CANCELLED,

    /** No platform key, no strong biometric, or the server's policy forbids it. */
    NOT_AVAILABLE,

    /**
     * The vault is not open, or it locked, the session changed or a newer enrolment started while the prompt was up
     * (this enrolment's "stale"): nothing was sealed or kept.
     */
    NOT_OPEN,

    /** The platform could not seal. */
    FAILED,
}

/** What a quick unlock came to. Nothing is sent by it. */
enum class QuickUnlockOutcome {
    UNLOCKED,

    /** The person cancelled the prompt: silent. */
    CANCELLED,

    /** It cannot be used now (not enrolled, not allowed, the periodic full password is due) or the biometric refused: use the password. */
    USE_PASSWORD,

    /** The sealed key is gone (the biometrics changed, or it no longer opens): quick unlock is off. */
    TURNED_OFF,

    /** The origin's pin record is damaged or gone: nothing was prompted or opened. */
    BLOCKED,

    /** The released key did not open the stored account (§5.2): nothing was opened, and quick unlock is off. */
    IDENTITY_FAULT,

    /** No session is kept. */
    NO_SESSION,
}

/**
 * What one confirmation of the person's presence came to ([QuickUnlockKeeper.confirmPresence]): the strong fingerprint
 * or face check that quick unlock uses, for an account that is already open. Nothing is sent by it, and it never
 * unlocks anything.
 */
enum class PresenceOutcome {
    /** The sealed key opened behind the prompt and is the open account's own key: the person is here. */
    CONFIRMED,

    /** The person cancelled the prompt: silent. Quick unlock stays on. */
    CANCELLED,

    /**
     * Ask for the master password instead: every reason for which quick unlock itself would ask for it (no strong
     * fingerprint or face check on this device, quick unlock not switched on for this account, the server's policy
     * does not allow it, the periodic full password is due), or the check refused (a lockout, a sensor error, no screen
     * to show the prompt on). Quick unlock stays as it was.
     */
    USE_PASSWORD,

    /**
     * The sealed record did not open, or opened to something that is not the open account's key: it was wiped, as a
     * failed quick unlock wipes it, and quick unlock is off. Ask for the master password instead.
     */
    TURNED_OFF,

    /**
     * This confirmation's own "stale" (spec 01, "Keys in memory and the lock", rule 5): nothing was confirmed, and
     * nothing is the person's to answer here. No vault was open; the vault locked, or the open session changed, while
     * the prompt was up; quick unlock was switched on again meanwhile; or another confirmation was already up (that one
     * answers). Nothing was wiped for it.
     */
    STALE,
}

/**
 * Quick unlock of the kept session (spec 01 §8.1, design 2026-07-10 and 2026-08-23 §7.1) over the platform's
 * [PlatformKeyWrap]. The account's key (its UVK), never the password, is sealed under the platform key; a quick unlock
 * opens the stored account with it as a password unlock does ([SessionKeeper.unlockWithUvk]), so:
 *
 * - **It sends nothing**, and nothing derived from the password exists in it; it works offline.
 * - **A damaged pin refuses** it before any prompt; **a fork does not**: the device's own copy opens, read-only, as
 *   the password unlock does (§4.4).
 * - **The periodic full password (A1/A2):** it is usable only within 30 days of the last full-password use on this
 *   device ([QuickUnlockRules.isFreshPure]), measured on the monotonic clock and the high-water wall clock; across a
 *   reboot, with no server-attested time after the stamp, it fails closed. Turning it on never renews the stamp.
 * - **The policy (A4):** usable only while the origin's last policy, seen within 7 days, permits key material at rest.
 *   A policy that forbids it removes the sealed key.
 * - **It goes** with the session (sign-out, a refused refresh, a forgotten server), when its server moves, when the
 *   platform key is invalidated, and when the person turns it off.
 * - **The offer** shows once, and after "Not now" comes back only after [QuickUnlockRules.QU_REOFFER_AFTER] password
 *   unlocks, at most [QuickUnlockRules.QU_REOFFER_MAX] times ([QuickUnlockRules.reofferDecision]).
 *
 * The sealed key is kept in [secure] (the session-grade store), the stamp and the offer in [state].
 */
class QuickUnlockKeeper(
    private val keeper: SessionKeeper,
    private val wrap: PlatformKeyWrap,
    private val secure: DeviceState,
    private val state: DeviceState,
    private val trust: InstanceTrust,
    private val policies: KeptPolicies,
    private val clocks: Clocks,
    private val crypto: CryptoProvider,
) {
    @Serializable
    private data class Sealed(val origin: String, val userId: String, val slot: String, val sealed: String)

    @Serializable
    private data class Stamp(val origin: String, val userId: String, val wallMs: Long, val monotonicMs: Long, val bootRefMs: Long, val bootId: String? = null)

    @Serializable
    private data class Offer(val dismissed: Boolean, val unlocks: Int, val reoffers: Int)

    init {
        keeper.quick = this
    }

    /** Quick unlock for the kept session; everything false when there is none. */
    fun status(): QuickUnlockStatus {
        val s = keeper.session ?: return QuickUnlockStatus(false, false, false, false, false)
        val available = wrap.strongBiometric()
        val allowed = allowed(s.origin)
        val enrolled = sealedFor(s.origin, s.userId) != null
        val usable = available && allowed && enrolled && fresh(s.origin, s.userId)
        val offerNow = available && allowed && !enrolled && !offer(s.origin, s.userId).dismissed
        return QuickUnlockStatus(available, allowed, enrolled, usable, offerNow)
    }

    private fun allowed(origin: String): Boolean {
        val p = policies.get(origin) ?: return false
        return QuickUnlockRules.policyPermits(p.offlineCacheAllowed, p.fetchedAtMs, clocks.wallMs())
    }

    /** Seal the open account's key under a fresh platform key, after the prompt. Sends nothing. */
    suspend fun enrol(): QuickEnrolOutcome {
        val open = keeper.established ?: return QuickEnrolOutcome.NOT_OPEN
        if (!wrap.strongBiometric() || !allowed(open.origin)) return QuickEnrolOutcome.NOT_AVAILABLE
        val origin = open.origin
        val userId = open.userId
        val slot = slotFor(origin, userId)
        val mine = kotlinx.atomicfu.locks.synchronized(enrolLock) { ++enrolments }
        // The consent first, with no key out of the guard: the prompt is a wait the guard cannot
        // be held across, so nothing of the UVK crosses it.
        val prepared = when (val p = wrap.prepare(slot, aad(origin, userId))) {
            is KeyWrapPrepare.Prepared -> p.sealer
            KeyWrapPrepare.Cancelled -> {
                if (latest(mine)) wrap.destroy(slot)
                return QuickEnrolOutcome.CANCELLED
            }
            KeyWrapPrepare.Failed -> {
                if (latest(mine)) wrap.destroy(slot)
                return QuickEnrolOutcome.FAILED
            }
        }
        // A second enrolment started while this prompt was up made the slot's key anew: this one's screen is gone, and
        // the slot is the newer one's.
        if (!latest(mine)) {
            prepared.discard()
            return QuickEnrolOutcome.NOT_OPEN
        }
        // The vault may have locked, or the session changed, while the prompt was up: then nothing is sealed or kept.
        val now = keeper.established
        val sealed = if (now == null || now.origin != origin || now.userId != userId || now.account !== open.account) {
            null
        } else {
            try {
                // After the prompt, sealed inside the guarded use: the platform is lent the guard's own buffer and seals
                // at once; a lock during the prompt makes the use refuse, and nothing is sealed.
                open.account.uvk.use { prepared.seal(it) } ?: run {
                    prepared.discard()
                    wrap.destroy(slot)
                    return QuickEnrolOutcome.FAILED
                }
            } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
                null
            }
        }
        if (sealed == null) {
            prepared.discard()
            wrap.destroy(slot)
            return QuickEnrolOutcome.NOT_OPEN
        }
        // A policy that forbids key material at rest may have been recorded while the prompt was up: looked at again
        // before the write, and once more after it (a record between the two found nothing to remove), so no key stays.
        if (!allowed(origin)) {
            wrap.destroy(slot)
            return QuickEnrolOutcome.NOT_AVAILABLE
        }
        secure.set(KEY_SEALED, WireJson.json.encodeToString(Sealed.serializer(), Sealed(origin, userId, slot, Bytes.toB64(sealed))))
        if (!allowed(origin)) {
            wipe()
            return QuickEnrolOutcome.NOT_AVAILABLE
        }
        return QuickEnrolOutcome.ENROLLED
    }

    private val enrolLock = kotlinx.atomicfu.locks.SynchronizedObject()

    /** How many enrolments have started; only the newest may keep the slot's key. Read and written under [enrolLock]. */
    private var enrolments = 0

    private fun latest(mine: Int): Boolean = kotlinx.atomicfu.locks.synchronized(enrolLock) { enrolments == mine }

    /** Turn it off: the sealed key and its platform key go. */
    fun turnOff() = wipe()

    /** "Not now" on the offer: it comes back only as [QuickUnlockRules.reofferDecision] allows. */
    fun notNow() {
        val s = keeper.session ?: return
        val o = offer(s.origin, s.userId)
        putOffer(s.origin, s.userId, Offer(true, 0, o.reoffers))
    }

    /** Open the kept session with the sealed key, behind the platform's prompt. Sends nothing. */
    suspend fun unlock(): QuickUnlockOutcome {
        val s = keeper.session ?: return QuickUnlockOutcome.NO_SESSION
        if (keeper.established != null) return QuickUnlockOutcome.UNLOCKED
        // A damaged pin record, or none, gives nothing to open against: refused before any prompt.
        if (!trust.access(s.origin).mayReadLocal || trust.pinState(s.origin) == PinState.None) return QuickUnlockOutcome.BLOCKED
        val sealed = sealedFor(s.origin, s.userId) ?: return QuickUnlockOutcome.USE_PASSWORD
        if (!wrap.strongBiometric() || !allowed(s.origin) || !fresh(s.origin, s.userId)) return QuickUnlockOutcome.USE_PASSWORD
        val bytes = runCatching { Bytes.fromB64(sealed.sealed) }.getOrNull()
        if (bytes == null) {
            wipe()
            return QuickUnlockOutcome.TURNED_OFF
        }
        return when (val r = wrap.open(sealed.slot, bytes, aad(s.origin, s.userId))) {
            is KeyWrapOpen.Opened -> {
                // The session may have changed under the prompt: the key is for the account it was sealed for only.
                val now = keeper.session
                if (now == null || now.origin != s.origin || now.userId != s.userId) {
                    r.secret.fill(0)
                    return QuickUnlockOutcome.NO_SESSION
                }
                when (keeper.unlockWithUvk(r.secret)) {
                    KeptUnlock.Unlocked -> QuickUnlockOutcome.UNLOCKED
                    KeptUnlock.Blocked -> QuickUnlockOutcome.BLOCKED
                    KeptUnlock.NoSession -> QuickUnlockOutcome.NO_SESSION
                    // Another unlock ran, or a lock came meanwhile: nothing opened, and the key stays.
                    KeptUnlock.Stale -> QuickUnlockOutcome.NO_SESSION
                    // The account's keys are kept at the server only (a forbidding policy): no key at rest is of use.
                    is KeptUnlock.KeysAtServer -> {
                        wipe()
                        QuickUnlockOutcome.USE_PASSWORD
                    }
                    else -> {
                        wipe()
                        QuickUnlockOutcome.IDENTITY_FAULT
                    }
                }
            }
            KeyWrapOpen.Cancelled -> QuickUnlockOutcome.CANCELLED
            KeyWrapOpen.Refused -> QuickUnlockOutcome.USE_PASSWORD
            KeyWrapOpen.Invalidated -> {
                wipe()
                QuickUnlockOutcome.TURNED_OFF
            }
        }
    }

    /**
     * Confirm the person's presence with the check quick unlock uses, for the account that is open now (design
     * 2026-11-15 §8.2 step 6: a device link is approved after Face ID, fingerprint or the master password, never the
     * device's PIN or passcode). It opens the sealed key behind the platform's prompt, which says [reason]
     * ([PlatformKeyWrap.openToConfirm]), and compares it in constant time with the open account's key inside the
     * account's guard: [PresenceOutcome.CONFIRMED] only when they are the same key and the vault is still open, as the
     * same session, after the prompt.
     *
     * - **It never unlocks**: with no vault open it refuses ([PresenceOutcome.STALE]) before any prompt.
     * - **The opened key stays in the guard**: it is read only inside the guarded use that compares it, and zeroed
     *   there and again on every other path before this returns; it is never kept, copied or handed on.
     * - **It sends nothing**, changes nothing about when quick unlock goes stale, and is not a use of the password.
     * - **A lock during the prompt wins**: the answer is [PresenceOutcome.STALE], never "confirmed", and a lock is never
     *   read as a key that is not the account's. One confirmation at a time: a second call while one is up answers
     *   [PresenceOutcome.STALE] with no prompt.
     */
    suspend fun confirmPresence(reason: String? = null): PresenceOutcome {
        val open = keeper.established ?: return PresenceOutcome.STALE
        val up = kotlinx.atomicfu.locks.synchronized(enrolLock) { if (presenceUp) false else true.also { presenceUp = true } }
        if (!up) return PresenceOutcome.STALE
        try {
            val origin = open.origin
            val userId = open.userId
            // Every reason for which quick unlock itself would ask for the password, decided before any prompt.
            val sealed = sealedFor(origin, userId) ?: return PresenceOutcome.USE_PASSWORD
            if (!wrap.strongBiometric() || !allowed(origin) || !fresh(origin, userId)) return PresenceOutcome.USE_PASSWORD
            val enrolAt = kotlinx.atomicfu.locks.synchronized(enrolLock) { enrolments }
            val bytes = runCatching { Bytes.fromB64(sealed.sealed) }.getOrNull()
            if (bytes == null) {
                wipe()
                return PresenceOutcome.TURNED_OFF
            }
            val r = wrap.openToConfirm(sealed.slot, bytes, aad(origin, userId), reason)
            // What the prompt was up over may have changed meanwhile: the vault locked or its session changed, or quick
            // unlock was switched on again (a newer record and key, which a wipe here must not touch).
            val stillOpen = keeper.established === open
            val sameRecord = latest(enrolAt) && sealedRecord() == sealed
            return when (r) {
                is KeyWrapOpen.Opened -> {
                    val opened = r.secret
                    try {
                        if (!stillOpen || !sameRecord) return PresenceOutcome.STALE
                        val same = try {
                            open.account.uvk.use { key ->
                                try {
                                    Bytes.ctEquals(key, opened)
                                } finally {
                                    opened.fill(0)
                                }
                            }
                        } catch (e: io.silencelen.andvari.core.crypto.KeysGoneException) {
                            // A lock that came after the prompt's answer: a lock, never a key that is not the account's.
                            return PresenceOutcome.STALE
                        }
                        when {
                            !same -> {
                                wipe()
                                PresenceOutcome.TURNED_OFF
                            }
                            keeper.established !== open -> PresenceOutcome.STALE
                            else -> PresenceOutcome.CONFIRMED
                        }
                    } finally {
                        opened.fill(0)
                    }
                }
                KeyWrapOpen.Cancelled -> if (stillOpen) PresenceOutcome.CANCELLED else PresenceOutcome.STALE
                KeyWrapOpen.Refused -> if (stillOpen) PresenceOutcome.USE_PASSWORD else PresenceOutcome.STALE
                KeyWrapOpen.Invalidated -> when {
                    !sameRecord -> PresenceOutcome.STALE
                    else -> {
                        // The platform key is gone whether or not the vault is still open: the record no longer opens.
                        wipe()
                        if (stillOpen) PresenceOutcome.TURNED_OFF else PresenceOutcome.STALE
                    }
                }
            }
        } finally {
            kotlinx.atomicfu.locks.synchronized(enrolLock) { presenceUp = false }
        }
    }

    /** A confirmation of presence is up ([confirmPresence]). Read and written under [enrolLock]. */
    private var presenceUp = false

    /** The origin's policy was read again: a policy that forbids key material at rest removes the sealed key. */
    fun policySeen(origin: String, policy: KeptPolicy) {
        if (!policy.offlineCacheAllowed) sealedRecord()?.takeIf { it.origin == origin }?.let { wipe() }
    }

    // ---- the keeper's hooks ----

    /**
     * The master password was used in full on this device for the kept session ([origin], [userId]): a password
     * unlock, a sign-in, a registration, a link or a recovery. It stamps the A1 clock and counts toward the re-offer.
     */
    internal fun passwordUsed(origin: String, userId: String) {
        // A key sealed for another account (an earlier session on this device) is of no use any more.
        sealedRecord()?.let { if (it.origin != origin || it.userId != userId) wipe() }
        val now = clocks.wallMs()
        val mono = clocks.monotonicMs()
        state.set(KEY_STAMP, WireJson.json.encodeToString(Stamp.serializer(), Stamp(origin, userId, now, mono, now - mono, clocks.bootId())))
        bumpHighWater(now)
        if (sealedFor(origin, userId) != null) return
        val o = offer(origin, userId)
        val d = QuickUnlockRules.reofferDecision(QuickUnlockRules.ReofferInputs(o.dismissed, o.unlocks, o.reoffers))
        putOffer(origin, userId, Offer(o.dismissed && !d.reoffer, d.unlocks, d.reoffers))
    }

    /** The session ended or moved: the sealed key, its platform key and the stamp go. */
    internal fun wipe() {
        sealedRecord()?.let { wrap.destroy(it.slot) }
        secure.set(KEY_SEALED, null)
        state.set(KEY_STAMP, null)
    }

    // ---- records ----

    private fun sealedRecord(): Sealed? =
        secure.get(KEY_SEALED)?.let { runCatching { WireJson.json.decodeFromString(Sealed.serializer(), it) }.getOrNull() }

    private fun sealedFor(origin: String, userId: String): Sealed? = sealedRecord()?.takeIf { it.origin == origin && it.userId == userId }

    private fun offer(origin: String, userId: String): Offer =
        state.get(offerKey(origin, userId))?.let { runCatching { WireJson.json.decodeFromString(Offer.serializer(), it) }.getOrNull() }
            ?: Offer(false, 0, 0)

    private fun putOffer(origin: String, userId: String, o: Offer) =
        state.set(offerKey(origin, userId), WireJson.json.encodeToString(Offer.serializer(), o))

    private fun bumpHighWater(now: Long): Long {
        val hw = maxOf(state.get(KEY_HIGH_WATER)?.toLongOrNull() ?: 0L, now)
        state.set(KEY_HIGH_WATER, hw.toString())
        return hw
    }

    /** A1/A2: the last full-password use for this account is recent enough, on clocks the person cannot wind back. */
    private fun fresh(origin: String, userId: String): Boolean {
        val stamp = state.get(KEY_STAMP)?.let { runCatching { WireJson.json.decodeFromString(Stamp.serializer(), it) }.getOrNull() }
            ?.takeIf { it.origin == origin && it.userId == userId } ?: return false
        val now = clocks.wallMs()
        val highWater = bumpHighWater(now)
        return QuickUnlockRules.isFreshPure(
            QuickUnlockRules.FreshnessInputs(
                nowMs = now,
                elapsedNowMs = clocks.monotonicMs(),
                stampWallMs = stamp.wallMs,
                stampElapsedMs = stamp.monotonicMs,
                stampBootRefMs = stamp.bootRefMs,
                highWaterWallMs = highWater,
                // No server-attested time is kept by this keeper: across a reboot it fails closed (the password).
                serverFloorMs = 0L,
                bootIdNow = clocks.bootId(),
                stampBootId = stamp.bootId,
            ),
        )
    }

    private fun slotFor(origin: String, userId: String): String =
        "andvari.ovh." + Bytes.toHexLower(crypto.sha256("$origin|$userId".encodeToByteArray())).take(32) + ".qk"

    private fun aad(origin: String, userId: String): ByteArray = "andvari/ovh|quick-unlock|$origin|$userId".encodeToByteArray()

    private fun offerKey(origin: String, userId: String) = "ovh.quick.offer|$origin|$userId"

    companion object {
        /** The [secure] key of the sealed account key. */
        const val KEY_SEALED = "ovh.quick"
        const val KEY_STAMP = "ovh.quick.stamp"
        const val KEY_HIGH_WATER = "ovh.quick.hw"
    }
}
