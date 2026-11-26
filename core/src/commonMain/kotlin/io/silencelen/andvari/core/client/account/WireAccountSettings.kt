package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.KdfUpgrade
import io.silencelen.andvari.core.client.Strength
import io.silencelen.andvari.core.client.recovery.ServedCost
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.OpenedAccount
import io.silencelen.andvari.core.client.onboard.PasswordKeys
import io.silencelen.andvari.core.client.onboard.RevealedKit
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.MemberRecoveryBlock
import io.silencelen.andvari.core.model.wire.PasswordChangeRequest
import io.silencelen.andvari.core.model.wire.ReauthRequest
import io.silencelen.andvari.core.model.wire.RecoverySelfSetupRequest
import io.silencelen.andvari.core.model.wire.RecoverySelfSetupResponse
import io.silencelen.andvari.core.model.wire.RequireLinkPut
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.RecoveryKit
import io.silencelen.andvari.core.trust.TrustGrammar

/**
 * The signed-in account's re-authenticated settings: the master password (spec 03 §3), the kit rotation
 * (`PUT /recovery/self-setup`, design §10) and "Your devices" with "New devices must be linked" (design §8.6,
 * §8.7; spec 03 §16.7, §16.8).
 *
 * Every `†` action derives `currentAuthKey` through the one [Reauth] path ([PasswordGate] purpose `reauth`, this
 * session's origin and account), and only then sends. Every password array handed in is wiped before the call
 * returns. [account] is borrowed from the session (its UVK re-wraps; its identity names the kit's account ID);
 * [card0Hash] is the pinned card 0, for the kit QR.
 */
class WireAccountSettings(
    private val origin: String,
    /** The signed-in account's address; [WireRecoverySettings] names it in every recovery copy it seals (spec 04 §3). */
    internal val emailNorm: String,
    private val card0Hash: String,
    private val account: OpenedAccount,
    private val client: WireClient,
    private val crypto: CryptoProvider,
    private val reauth: Reauth,
    /**
     * The account's own cost, which a new master password is never derived below. Spec 01 §7: the caller names the
     * account's own cost (a pending wrap's when that is higher); [changeWrap] raises it, figure by figure, to the cost the
     * server serves at that moment ([KdfUpgrade.wrapCost]). A caller that never changes the password through this object
     * may still leave it out (the default is going: name it).
     */
    private val kdfParams: KdfParams = KdfParams.DEFAULT,
    /**
     * This session's device id. Given, the devices list must mark exactly this device `current` ([DevicePages]): a list
     * of another account, or a page of another session's view, is refused. Null: only the page rules apply. Every host
     * passes it (the session holds it).
     */
    private val thisDevice: String? = null,
) : PasswordChange, DeviceSettings {

    /** [Reauth] for [password] (wiped), then [send] with the key; a refused gate or prelogin sends nothing. */
    private suspend fun <T> reauthed(password: CharArray, send: suspend (String) -> Reauthed<T>): Reauthed<T> {
        val key = try {
            reauth.currentAuthKey(password)
        } finally {
            password.fill('\u0000')
        }
        return when (key) {
            is ReauthKey.Key -> send(key.currentAuthKey)
            ReauthKey.Refused -> Reauthed.NoSession
            ReauthKey.Unreachable -> Reauthed.Unknown
            ReauthKey.WrongPassword -> Reauthed.WrongPassword
        }
    }

    private fun <T> answer(r: WireResult<*>, value: () -> T): Reauthed<T> = when (r) {
        is WireResult.Ok -> Reauthed.Done(value())
        is WireResult.Refused -> when {
            // The server refused the proof: never a wrong password typed here (that one sends nothing).
            r.code == Reauthed.PROOF_REFUSED -> Reauthed.Refused(Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
            r.status >= 500 -> Reauthed.Unknown
            else -> Reauthed.Refused(r.code, r.retryAfterSeconds)
        }
        is WireResult.NoAnswer -> Reauthed.Unknown
    }

    override suspend fun change(currentPassword: CharArray, newPassword: CharArray): Reauthed<Unit> =
        when (val r = changeWrap(currentPassword, newPassword)) {
            is Reauthed.Done -> Reauthed.Done(Unit)
            Reauthed.NoSession -> Reauthed.NoSession
            Reauthed.WrongPassword -> Reauthed.WrongPassword
            Reauthed.PasswordTooWeak -> Reauthed.PasswordTooWeak
            is Reauthed.Refused -> r
            Reauthed.Unknown -> Reauthed.Unknown
        }

    /**
     * [change], answering with exactly the wrap that was sent and accepted ([NewWrap]: salt, parameters and the UVK
     * wrapped under the new password). The device keeps that one, so its own wrap stays the server's (same salt, same
     * cost), no key is used after the answer, and the next re-authentication proves the password against it and derives
     * `currentAuthKey` from it (spec 01 §7).
     *
     * The order, each step for its own reason:
     * 1. The re-authentication proves the current password on this device ([Reauth]) before anything at all is sent: a
     *    wrong one sends nothing, not even the read of the served cost (spec 01 §7: a wrong password sends nothing).
     * 2. That proof is a wait (the KDF): `guard.check()` sees a lock that came during it, before anything is read or sent
     *    ([KeysGoneException], which the engine answers as overtaken).
     * 3. Only then the served cost is read (`GET /client-policy`, a request that carries nothing of the account), and the
     *    new keys are derived at, figure by figure, the higher of the account's own and that cost ([KdfUpgrade.wrapCost]).
     * 4. The new wrap is sealed under the account's guard, as [rotateKit] seals its piece: a
     *    lock that came during the derivation refuses it ([KeysGoneException], nothing sent).
     * 5. [beforeSend] is given the wrap, so the device keeps it as pending before the request goes.
     * 6. The request.
     * Both password arrays are wiped whatever happens.
     */
    suspend fun changeWrap(currentPassword: CharArray, newPassword: CharArray, beforeSend: (NewWrap) -> Unit = {}): Reauthed<NewWrap> {
        if (!Strength.meetsMasterPasswordFloor(newPassword)) {
            newPassword.fill('\u0000')
            currentPassword.fill('\u0000')
            return Reauthed.PasswordTooWeak
        }
        try {
            return reauthed(currentPassword) { current ->
                // The re-authentication was a wait: a lock that came during it reads nothing and sends nothing.
                account.guard.check()
                // The cost of the new wrap: figure by figure the higher of the account's own (the caller's [kdfParams]) and
                // what the server serves now, inside the fence (spec 01 §7; decided on 2026-11-17). Read only now that the
                // typed password has been proved here, so a wrong password sends nothing at all.
                val cost = KdfUpgrade.wrapCost(ServedCost.read(client), kdfParams)
                val keys = PasswordKeys.derive(crypto, newPassword, crypto.randomBytes(KdfParams.SALT_BYTES), cost, served = false)
                    ?: return@reauthed Reauthed.Refused("bad_kdf")
                try {
                    // The derivation was a wait: a lock that came during it refuses the seal, and nothing is kept or sent.
                    val wrapped = account.uvk.use { Envelope.sealB64(crypto, keys.wrapKey, it, Ad.uvk(account.userId)) }
                    val wrap = NewWrap(Bytes.toB64(keys.salt), keys.params, wrapped)
                    account.guard.check()
                    val body = PasswordChangeRequest(current, keys.authKeyB64, wrap.kdfSalt, wrap.kdfParams, wrap.wrappedUvk)
                    beforeSend(wrap)
                    answer(client.call(WireRoute.PASSWORD_CHANGE, bodyJson = WireJson.json.encodeToString(PasswordChangeRequest.serializer(), body), decode = { })) { wrap }
                } finally {
                    keys.wipe()
                }
            }
        } finally {
            // Wiped by the derivation when it ran; here on every other way out (a wrong password, a lock, no session).
            newPassword.fill('\u0000')
        }
    }

    /** The wrap a password change sent: what the server holds once it answered, and what this device keeps then. */
    class NewWrap internal constructor(val kdfSalt: String, val kdfParams: KdfParams, val wrappedUvk: String)

    /**
     * `PUT /recovery/self-setup`† with a fresh recovery secret: the old kit stops working when the server answers.
     * The new kit goes through the capture gate ([io.silencelen.andvari.core.client.onboard.Onboarding.confirmKit]).
     */
    suspend fun rotateKit(password: CharArray): Reauthed<RevealedKit> {
        // The piece first, under the account's guard; the re-authentication is a wait, after which a lock sends nothing.
        val piece = try {
            account.uvk.use { MemberRecovery.generate(crypto, account.userId, it) }
        } catch (e: KeysGoneException) {
            password.fill('\u0000')
            throw e
        }
        try {
            return reauthed(password) { current ->
                account.guard.check()
                val body = RecoverySelfSetupRequest(current, MemberRecoveryBlock(piece.recoveryWrappedUvk, piece.recoveryAuthKey))
                val r = client.call(WireRoute.RECOVERY_SELF_SETUP, bodyJson = WireJson.json.encodeToString(RecoverySelfSetupRequest.serializer(), body),
                    decode = { WireJson.json.decodeFromString(RecoverySelfSetupResponse.serializer(), it) })
                if (r is WireResult.Ok && !TrustGrammar.isB64_32(r.value.pieceId)) return@reauthed Reauthed.Unknown
                val qr = RecoveryKit.composeQr(origin, card0Hash, emailNorm, piece.recoverySecret) ?: return@reauthed Reauthed.Refused("bad_kit")
                answer(r) { RevealedKit(RecoveryKit.groups(piece.recoverySecret), qr, (r as WireResult.Ok).value.pieceId, account.accountId(crypto), piece.recoverySecret.copyOf()) }
            }
        } finally {
            piece.recoverySecret.fill(0)
        }
    }

    /** Every page of the account's devices ([DevicePages]: the whole list only once its last page arrived). */
    override suspend fun list(): Fetched<List<Device>> = DevicePages.readAll(client, WireRoute.DEVICES, thisDevice = thisDevice)

    override suspend fun revoke(deviceId: String, password: CharArray): Reauthed<Unit> {
        if (!TrustGrammar.isUuid(deviceId)) {
            password.fill('\u0000')
            return Reauthed.Refused("bad_device_id")
        }
        return reauthed(password) { current ->
            answer(client.call(WireRoute.DEVICE_REVOKE, pathParams = mapOf("deviceId" to deviceId),
                bodyJson = WireJson.json.encodeToString(ReauthRequest.serializer(), ReauthRequest(current)), decode = { })) { }
        }
    }

    override suspend fun setRequireLink(enabled: Boolean, password: CharArray): Reauthed<Boolean> = reauthed(password) { current ->
        answer(client.call(WireRoute.REQUIRE_LINK, bodyJson = WireJson.json.encodeToString(RequireLinkPut.serializer(), RequireLinkPut(enabled, current)), decode = { })) { enabled }
    }
}
