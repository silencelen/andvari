package io.silencelen.andvari.core.app

/** "Your devices" (§8.6), and "New devices must be linked" (§8.7). */
class DevicesScreen internal constructor(
    /** This device first, then the others by when they were last seen. */
    val devices: List<DeviceRow>,
    /** "New devices must be linked from one of mine" is on: a password sign-in from a device the account does not know is refused. */
    val requireLink: Boolean,
    /**
     * [requireLink] is known: it is what THIS device set during this session (another device may have changed it
     * since). The server serves no read of the setting (spec 03 §16.8 has only the `PUT`), so until this device sets it
     * [requireLink] is false and means nothing: show the switch without a state and offer both "on" and "off", each
     * behind the master password ([DevicesApi.setRequireLink]). It is forgotten at sign-out, kept across a lock.
     */
    val requireLinkKnown: Boolean = true,
) {
    /** §4.4, always shown on this screen: revoking a lost device stops it syncing and does not wipe it (a placeholder key, [CopyKey.awaitingOwner]). */
    val revokeLine: CopyLine get() = CopyLine.of(CopyKey.DEVICES_REVOKE_DOES_NOT_WIPE)
}

/** One device of the account, as the server lists it (the wire's `Device`). */
class DeviceRow internal constructor(
    val deviceId: String,
    val platform: AppPlatform,
    /** The device's own name for itself. Plain text; the device chose it. */
    val name: String,
    val clientVersion: String,
    val addedAtMs: Long,
    /** 0 when the server has none. */
    val lastSeenAtMs: Long,
    /** It still holds a session that is neither revoked nor expired. */
    val live: Boolean,
    val how: HowDeviceJoined,
    /** [HowDeviceJoined.LINKED]: the name of the device it was linked from; empty otherwise. */
    val linkedFrom: String,
    /** This device. It cannot revoke itself; signing out does that. */
    val current: Boolean,
)

/** The wire's `how` values, typed. */
enum class HowDeviceJoined {
    /** The device the account was created on. */
    REGISTERED,

    /** Signed in with the address and the master password. */
    PASSWORD,

    /** Linked from another device of the account. */
    LINKED,

    /** Signed in by a recovery, with the kit or the operator's help. */
    RECOVERED,
    NOT_KNOWN,
}

/**
 * Linking a new device from this one (§8.2, the existing device's side). One to one with the engine's
 * `ExistingStep`. **This side never shows a code**: the person types the digits the new device shows.
 */
sealed class DeviceLinkHost {
    /**
     * `ExistingStep.Shown`: the link exists. Show its QR ([DevicesApi.deviceLinkToShow]) with [line], which names
     * the instance and its origin so the person can compare it with the address the new device shows, and count down
     * from [DevicesApi.deviceLinkTimeLeftMs].
     */
    class Shown internal constructor(val instance: InstanceLabel) : DeviceLinkHost() {
        val line: CopyLine get() = CopyLine.of(CopyKey.DEVICE_LINK_SHOW, instance.name, instance.origin)
    }

    /**
     * `ExistingStep.ClaimFixed`: a device claimed the link, its claim's MAC verified, and this device fixed the
     * claim and sent its nonce. The new device has yet to reveal.
     */
    class Claimed internal constructor(
        /** The name the claiming device gave itself. Plain text, and nothing vouches for it. */
        val deviceName: String,
        val platform: AppPlatform,
    ) : DeviceLinkHost()

    /**
     * `ExistingStep.TypeDigits`: the new device revealed, and its reveal matches what it committed to. **It exists
     * only then, and it is the only state [DevicesApi.submitDeviceDigits] takes**, so the digits cannot be asked
     * for, or accepted, against a code the other side could still choose.
     */
    class TypeDigits internal constructor(val deviceName: String, val platform: AppPlatform) : DeviceLinkHost() {
        val line: CopyLine get() = CopyLine.of(CopyKey.DEVICE_LINK_ADD, deviceName, platform.wireName)
    }

    /** `ExistingStep.Approvable`: the typed digits matched. Approve after Face ID, fingerprint or the master password. */
    class Approvable internal constructor(
        val deviceName: String,
        val platform: AppPlatform,
        /** Quick unlock is set up on this device, so the approval can use it. */
        val biometricsOffered: Boolean,
    ) : DeviceLinkHost()

    /**
     * `ExistingStep.Approved`: approved. **This is where the existing device's part ends.** The new device still has
     * to prove the master password; no device and no session exists until it does, and this device is not told
     * when it has: the new device appears in [DevicesScreen] once it is there ([DevicesApi.openDevices]).
     * [DevicesApi.dismissDeviceLink] closes the screen.
     */
    class Approved internal constructor(val deviceName: String) : DeviceLinkHost()

    /** The link ended without an approval (`ExistingStep.Stopped`). */
    class Ended internal constructor(
        val outcome: DeviceLinkHostEnd,
        /**
         * A line of its own where [outcome] has none that is true, shown in its place: [CopyKey.DEVICE_LINK_HOST_TOO_MANY]
         * where the server refused a step of the link as one of too many requests (never "unreachable", never "a check
         * failed"; the wait is [AppApi.retryAfterSeconds]). Null otherwise. Additive: [outcome] is then
         * [DeviceLinkHostEnd.DID_NOT_CHECK_OUT], so that no app's reading of it breaks.
         */
        val line: CopyKey? = null,
        /**
         * The wait the server named with a [CopyKey.DEVICE_LINK_HOST_TOO_MANY] end, kept with this end: what is left of it,
         * and whether it is over. Null where the server named none, and for every other end. Additive.
         */
        val wait: NamedWait? = null,
    ) : DeviceLinkHost() {
        /**
         * The end's own line as it stands now: [CopyKey.DEVICE_LINK_HOST_TOO_MANY_WAIT_OVER] once the wait the server named
         * is over (never "the server named no wait"); [line] otherwise, whose {0} is [NamedWait.secondsLeft] while the wait
         * runs. Read it again as time passes.
         */
        fun lineNow(): CopyKey? =
            if (line == CopyKey.DEVICE_LINK_HOST_TOO_MANY && wait?.over == true) CopyKey.DEVICE_LINK_HOST_TOO_MANY_WAIT_OVER else line
    }
}

/** How a device link ended on the existing device without being approved. */
enum class DeviceLinkHostEnd(val sentence: CopyKey?) {
    /**
     * Cancelled here, or a newer link was made for the account, on this device or another: making one cancels every
     * earlier link that was not picked up (S3-C3). The server's answer does not tell the two apart.
     */
    CANCELLED(CopyKey.DEVICE_LINK_CANCELLED),

    /** The digits typed here did not match: the link was cancelled. */
    CODE_MISMATCH(CopyKey.DEVICE_LINK_CANCELLED),

    /** One of the link's steps ran out of time. */
    EXPIRED(null),

    /** A check failed (the claim's MAC, a claim that changed after it was fixed, a reveal that does not match). */
    DID_NOT_CHECK_OUT(null),
}

interface DevicesApi {
    suspend fun openDevices(): PlainResult

    fun closeDevices()

    /**
     * Revoke another device of the account. It stops being a device the account knows (FC-8). **Offer it for every
     * row but [DeviceRow.current], live or not:** a device that signed out or sat idle is not [DeviceRow.live] yet is
     * still a known device (§8.7), so "New devices must be linked" does not stop it until it is revoked; the list
     * cannot tell it from a device revoked already, and revoking that one again is harmless. The list is read again
     * after the answer (not after [ProofResult.WRONG_PASSWORD]).
     */
    suspend fun revokeDevice(device: DeviceRow, password: String): ProofResult

    /** Turn "New devices must be linked" on or off (§8.7). */
    suspend fun setRequireLink(enabled: Boolean, password: String): ProofResult

    /**
     * Make a device link and show it ([AccountSnapshot.deviceLink]). It cancels every earlier link of the account
     * that was not picked up, on any device.
     */
    suspend fun startDeviceLink(): PlainResult

    /** The link itself, for the QR and "Share link". An explicit read, because it carries the link's secret. Null once the link moved on. */
    fun deviceLinkToShow(screen: DeviceLinkHost.Shown): String?

    /**
     * How long the link's current step still has, in milliseconds, counted down from what the server answered on a
     * clock the person cannot set, never from the device's own time (SR-1). 0 when no link is running.
     */
    fun deviceLinkTimeLeftMs(): Long

    /**
     * The six digits the new device shows, **as the person typed them here**: pass the field's text through
     * untouched. The engine compares it as text under the rule of §6.11 (every ASCII space removed, then exactly six
     * ASCII digits). **A tap is not enough, and there is no other way to say the codes agree.** Unlike a link's
     * comparison code, a mismatch here cancels the link.
     */
    suspend fun submitDeviceDigits(screen: DeviceLinkHost.TypeDigits, digits: String): DigitsResult

    /** Approve with the master password. */
    suspend fun approveWithPassword(screen: DeviceLinkHost.Approvable, password: String): ProofResult

    /**
     * Approve with Face ID or fingerprint, where quick unlock is set up ([DeviceLinkHost.Approvable.biometricsOffered]):
     * the system's prompt opens this device's quick-unlock key, which must be the open account's own. Never the device's
     * PIN or passcode. [ProofResult.DONE] approved; [ProofResult.CANCELLED] leaves the link as it is;
     * [ProofResult.BIOMETRICS_NOT_USED] asks for the master password ([approveWithPassword]); [ProofResult.STALE] (a
     * lock overtook it) approved nothing. [reason] is what the prompt says, naming the new device; null for the default.
     */
    suspend fun approveWithBiometrics(screen: DeviceLinkHost.Approvable, reason: String?): ProofResult

    /** Cancel the running link, in any state before the new device picked up. */
    suspend fun cancelDeviceLink(): PlainResult

    /** Close the screen of a link that is approved ([DeviceLinkHost.Approved]) or ended ([DeviceLinkHost.Ended]). */
    fun dismissDeviceLink()
}

/**
 * An intent that needs the person's proof: the master password on a re-authenticated route, or the device's own
 * unlock. **A wrong master password is its own answer, [WRONG_PASSWORD], on every such intent**: the server answers
 * it `403 reauth_failed`, never `401`, so it can never read as "your session expired" (S3-K1).
 */
enum class ProofResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    DONE,
    WRONG_PASSWORD,

    /**
     * The server refused the password's proof while this session knows that the account's keys on the server are not
     * the ones this device knows: nothing was changed; sign in again on this device. Additive.
     */
    KEYS_NOT_KNOWN_HERE(sentence = CopyKey.KEYS_NOT_KNOWN_HERE),

    /**
     * The server refused the proof of a password that opened this account on this device (decided on 2026-11-17: a wrong
     * password is found on the device and sends nothing, so a refusal after that is never one), while this session does
     * not know that the server's keys differ: nothing was changed. Additive.
     */
    PROOF_REFUSED(sentence = CopyKey.SERVER_REFUSED_PROOF),

    /**
     * The fingerprint or face check cannot answer now (quick unlock is not on here, was switched off by this check, is
     * locked out, or waits for the periodic master password): ask for the master password. Nothing was approved.
     */
    BIOMETRICS_NOT_USED,

    /** The person cancelled the fingerprint or face prompt: nothing was approved and the link stays as it is. Additive. */
    CANCELLED(sentence = CopyKey.DEVICE_APPROVAL_CANCELLED),

    /**
     * Approving a new device: the link's time ran out before the approval (a fingerprint or face prompt answered late, or
     * the server found it expired). Nothing was approved; the link ended ([DeviceLinkHostEnd.EXPIRED]). Additive.
     */
    LINK_EXPIRED(sentence = CopyKey.DEVICE_APPROVAL_LINK_EXPIRED),

    /** The password was changed on another device meanwhile (`401 credential_changed`). */
    CHANGED_ELSEWHERE,

    /** The device is gone already, or it is this one. */
    NOT_POSSIBLE,
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}

/** The digits typed into the existing device. */
enum class DigitsResult(override val trouble: Trouble? = null, override val sentence: CopyKey? = null) : IntentResult {
    /** They match: approve next. */
    DONE,

    /** They do not match: the link is cancelled ([DeviceLinkHostEnd.CODE_MISMATCH]). */
    MISMATCH(sentence = CopyKey.DEVICE_LINK_CANCELLED),
    STALE(Trouble.STALE),
    UNREACHABLE(Trouble.UNREACHABLE),
    RATE_LIMITED(Trouble.RATE_LIMITED),
    UPDATE_REQUIRED(Trouble.UPDATE_REQUIRED),
    FAILED(Trouble.FAILED),
    ;

    override val done: Boolean get() = this == DONE
}
