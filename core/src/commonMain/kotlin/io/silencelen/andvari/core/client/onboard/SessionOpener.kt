package io.silencelen.andvari.core.client.onboard

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoProvider
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.model.wire.AccountKeys
import io.silencelen.andvari.core.model.wire.SessionResponse
import io.silencelen.andvari.core.trust.TrustGrammar

/** What turning a served [SessionResponse] into an [EstablishedSession] came to. */
internal sealed class Opening {
    /**
     * Opened and handed to the sink. [notTaken] is the sink's reason when it did not keep the session (another account is
     * kept here, the address is bound to another account, the key is not the kept account's): it ended that session itself.
     * A sign-in says it as its refusal; null when the session was kept.
     */
    class Done(val session: EstablishedSession, val notTaken: String? = null) : Opening()

    /** The identity security fault (design §5.2): [reason] as [AccountOpenResult.IdentityFault]. */
    class Fault(val reason: String) : Opening()

    /**
     * The answer is not a session this request can have opened (an id outside the grammar, another user, keys that are
     * not the ones derived under or sent, or account-key texts not in their canonical form, [ServedKeyForm]).
     */
    data object Bad : Opening()
}

/**
 * What this device itself knows of the account's password keys when a session answer arrives: the [salt] and [params]
 * it derived under (the prelogin's, at a sign-in or a pickup; its own fresh ones, at a registration or a recovery
 * commit), and the [wrappedUvk] it sent (null when it sent none). The answer's `accountKeys` must carry exactly these:
 * the session keeps them, and the next unlock on this device derives under them, so a salt, parameters or wrap of
 * another account or of an earlier password would turn the person's own password into "wrong password" there.
 */
internal class KnownKdf(salt: ByteArray, val params: KdfParams, val wrappedUvk: String? = null) {
    private val salt = salt.copyOf()

    /** True when [keys] carry this salt, these parameters and (when one was sent) this wrap. */
    fun matches(keys: AccountKeys): Boolean {
        val served = Bytes.fromB64Canonical(keys.kdfSalt) ?: return false
        return Bytes.ctEquals(served, salt) && keys.kdfParams == params && (wrappedUvk == null || keys.wrappedUvk == wrappedUvk)
    }
}

/**
 * Design 2026-11-15 §2.2, strict decoding, for the account-key texts a server serves and this device keeps: the sealed
 * identity seed, the account key's wrap with its salt, and the personal vault's wrap. Each is taken only in its canonical
 * form (unpadded base64url that re-encodes to itself). A text in any other form is the server's fault and is refused
 * before anything of it is kept: kept as served, it would open later through a decoder that tolerates it, while a
 * stricter reading judged the same copy undecodable, and a healthy copy would be told to its owner as damaged.
 * (`identityPub` and the genesis are read strictly by [AccountOpen] itself, so a text of theirs in another form never
 * opens and is never kept.)
 */
internal object ServedKeyForm {
    /** Every account-key text of [keys] is in its canonical form. */
    fun canonical(keys: AccountKeys): Boolean =
        wrapCanonical(keys.kdfSalt, keys.wrappedUvk) &&
            Bytes.fromB64Canonical(keys.encryptedIdentitySeed) != null &&
            (keys.personalWrap?.let { Bytes.fromB64Canonical(it.wrappedVk) != null } ?: true)

    /** A served wrap of the account key: its salt and its sealed text, both in canonical form. */
    fun wrapCanonical(kdfSalt: String, wrappedUvk: String): Boolean =
        Bytes.fromB64Canonical(kdfSalt) != null && Bytes.fromB64Canonical(wrappedUvk) != null

    /** The same rule on the older account road's keys ([io.silencelen.andvari.core.model.AccountKeys]). */
    fun canonical(keys: io.silencelen.andvari.core.model.AccountKeys): Boolean =
        wrapCanonical(keys.kdfSalt, keys.wrappedUvk) &&
            Bytes.fromB64Canonical(keys.encryptedIdentitySeed) != null &&
            (keys.personalWrap?.let { Bytes.fromB64Canonical(it.wrappedVk) != null } ?: true)

    /** On the older account road: [keys] as served, refused with [ServedKeysNotCanonical] unless every text is canonical. */
    fun requireCanonical(keys: io.silencelen.andvari.core.model.AccountKeys): io.silencelen.andvari.core.model.AccountKeys {
        if (!canonical(keys)) throw ServedKeysNotCanonical()
        return keys
    }
}

/**
 * Design §2.2, strict decoding, on the older account road (the sign-in, the enrolment and the online unlock of
 * [io.silencelen.andvari.core.client.session.SessionEntry] and its ladder): the server served account-key texts in another
 * form than the canonical one. That is the server's fault; nothing of them was kept or opened.
 */
class ServedKeysNotCanonical : Exception("bad_response: the server's account keys are not in their canonical form")

/**
 * The one place a served session becomes this device's session (sign-in, registration, the recovery commits,
 * the device-link pickup): the ids are checked against the grammar (spec 05 R18), the keys' salt, parameters and wrap
 * against what the device derived under or sent ([KnownKdf]), the account opens through every identity check
 * ([AccountOpen]), the session is handed to the session layer ([SessionSink.take]), and, once it was kept, the device row
 * is remembered for the secret that made it. [uvk] is taken: wiped on every refusal.
 */
internal object SessionOpener {
    suspend fun open(
        crypto: CryptoProvider,
        origin: String,
        emailNorm: String,
        response: SessionResponse,
        uvk: ByteArray,
        expectedUserId: String?,
        pinnedInstanceId: String,
        knownIdentityPub: ByteArray?,
        deviceSecret: String,
        how: SessionHow,
        devices: KnownDevices,
        sink: SessionSink,
        kdf: KnownKdf,
        /** A sign-in's proof by a kept wrap ([KeptAccountCheck.provingKey]), taken: handed to the sink with the session, or wiped. */
        keptWrapKey: ByteArray? = null,
    ): Opening {
        try {
            return openWith(crypto, origin, emailNorm, response, uvk, expectedUserId, pinnedInstanceId, knownIdentityPub, deviceSecret, how, devices, sink, kdf) {
                it.giveKeptWrapKey(keptWrapKey?.copyOf())
            }
        } finally {
            keptWrapKey?.fill(0)
        }
    }

    private suspend fun openWith(
        crypto: CryptoProvider,
        origin: String,
        emailNorm: String,
        response: SessionResponse,
        uvk: ByteArray,
        expectedUserId: String?,
        pinnedInstanceId: String,
        knownIdentityPub: ByteArray?,
        deviceSecret: String,
        how: SessionHow,
        devices: KnownDevices,
        sink: SessionSink,
        kdf: KnownKdf,
        prove: (EstablishedSession) -> Unit,
    ): Opening {
        // A user id of all zeros is never an account (the escrow's canary uses it), whatever else the answer says.
        val idsOk = TrustGrammar.isUuid(response.userId) && !io.silencelen.andvari.core.client.UserIds.isNil(response.userId) &&
            TrustGrammar.isUuid(response.deviceId) &&
            (expectedUserId == null || expectedUserId == response.userId) &&
            (response.role == "member" || response.role == "operator") &&
            kdf.matches(response.accountKeys) &&
            // Keys in a form other than the canonical one are not the session this request can have opened ([ServedKeyForm]).
            ServedKeyForm.canonical(response.accountKeys)
        if (!idsOk) {
            uvk.fill(0)
            return Opening.Bad
        }
        val account = when (val o = AccountOpen.open(crypto, response.userId, uvk, response.accountKeys, pinnedInstanceId, knownIdentityPub)) {
            is AccountOpenResult.IdentityFault -> return Opening.Fault(o.reason)
            is AccountOpenResult.Opened -> o.account
        }
        val session = EstablishedSession(
            origin, emailNorm, response.userId, response.deviceId, response.role, response.totpEnrolled, response.mustEnrollTotp,
            response.accountKeys.recoveryConfirmed, how, response.accessToken, response.refreshToken, response.accountKeys, account,
        )
        prove(session)
        val notTaken = try {
            sink.take(session)
        } finally {
            // A sink that is not the keeper never takes it: it goes with this call.
            session.takeKeptWrapKey()?.fill(0)
        }
        // The device's record of its own id for the address follows only a session that was kept: an answer the sink
        // refused (another account answered for the address, say) leaves the record as it was.
        if (notTaken == null) devices.remember(origin, emailNorm, deviceSecret, response.deviceId)
        return Opening.Done(session, notTaken)
    }
}
