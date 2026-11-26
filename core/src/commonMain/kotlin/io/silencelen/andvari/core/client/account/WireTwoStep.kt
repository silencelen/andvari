package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.model.wire.TotpCodeRequest
import io.silencelen.andvari.core.model.wire.TotpDisableRequest
import io.silencelen.andvari.core.model.wire.TotpSetupRequest
import io.silencelen.andvari.core.model.wire.TotpSetupResponse
import io.silencelen.andvari.core.model.wire.TotpStatus
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute

/** `GET /account/totp` (spec 03 row 13), as the Settings screen shows it. */
data class TwoStepStatus(val enrolled: Boolean, val pendingSetup: Boolean)

/** The secret of a two-step setup (spec 03 row 14): pending until [TwoStep.confirm] answers [TwoStepAnswer.Ok]. */
class TwoStepSecret internal constructor(val secretBase32: String, val otpauthUri: String) {
    override fun toString() = "TwoStepSecret(…)"
}

/** What [TwoStep.setup] or [TwoStep.rotate] came to. */
sealed class TwoStepSetup {
    /** Show [secret] (its URI as a QR, its base32 text to type), then ask for a code for [TwoStep.confirm]. */
    class Ready internal constructor(val secret: TwoStepSecret) : TwoStepSetup()

    /**
     * The password typed here did not open this device's own wrap: nothing was sent. The server's `403 reauth_failed` is
     * [Refused] with [Reauthed.PROOF_REFUSED].
     */
    data object WrongPassword : TwoStepSetup()

    /** `403 reauth_required`: the server wants the master password (or, for an enrolled account, the current code). */
    data object ReauthRequired : TwoStepSetup()

    /** `400 bad_totp_code` (a rotation's current code), or a code that is not six digits: nothing was sent then. */
    data object BadCode : TwoStepSetup()

    /** The password gate refused at the entry (no session for this account at this origin, or its pin is forked or damaged): nothing sent. */
    data object NoSession : TwoStepSetup()

    /** Another refusal of the route (`rate_limited`, ...). */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : TwoStepSetup()

    /** No answer, a `5xx` or a reply that does not decode: a setup may be pending. [TwoStep.status] shows it. */
    data object Unknown : TwoStepSetup()
}

/** What [TwoStep.confirm] or [TwoStep.disable] came to. */
sealed class TwoStepAnswer {
    data object Ok : TwoStepAnswer()

    /** `400 bad_totp_code`, or a code that is not six digits (nothing was sent then). */
    data object BadCode : TwoStepAnswer()

    /** `400 no_pending_totp` (confirm): no setup is waiting; start one again. */
    data object NoPendingSetup : TwoStepAnswer()

    /** `400 totp_not_enrolled` (disable): two-step sign-in is already off. */
    data object NotEnrolled : TwoStepAnswer()

    /** `403 reauth_failed` (disable): the master password is wrong; the code was not looked at. */
    data object WrongPassword : TwoStepAnswer()

    /**
     * `403 reauth_required` (disable): the server wants the master password beside the code. Also the answer of the old
     * [WireTwoStep.disable] that takes the code alone, which since 2026-11-16 sends nothing.
     */
    data object ReauthRequired : TwoStepAnswer()

    /** The password gate refused at the entry: the code was not sent. */
    data object NoSession : TwoStepAnswer()

    /** Another refusal of the route (`rate_limited`, ...). */
    data class Refused(val code: String, val retryAfterSeconds: Long? = null) : TwoStepAnswer()

    /** No answer, a `5xx` or a reply that does not decode: the change may have landed. [TwoStep.status] shows it. */
    data object Unknown : TwoStepAnswer()
}

/**
 * Two-step sign-in in Settings (spec 03 rows 13 to 16, §2 "Server-TOTP management"), over the signed-in session's
 * client. A first setup re-authenticates through [Reauth] (the master password becomes `currentAuthKey`; the password
 * array is wiped before the call returns); turning it off, and a rotation of an enrolled account, send a current code and
 * the password's proof (since 2026-11-16 the server checks the proof first). A code is
 * one of the account's secrets (design §4.4 password rule): it goes only where [Reauth]'s gate proceeds, and a code
 * that is not six digits is answered here without a call.
 */
class WireTwoStep(private val client: WireClient, private val reauth: Reauth) {

    suspend fun status(): Fetched<TwoStepStatus> =
        when (val r = client.call(WireRoute.TOTP_STATUS, decode = { WireJson.json.decodeFromString(TotpStatus.serializer(), it) })) {
            is WireResult.Ok -> Fetched.Ok(TwoStepStatus(r.value.enrolled, r.value.pendingSetup))
            is WireResult.Refused -> if (r.status >= 500) Fetched.Unreachable else Fetched.Refused(r.code)
            is WireResult.NoAnswer -> Fetched.Unreachable
        }

    /** A first setup: re-authenticated with [password] (wiped). */
    suspend fun setup(password: CharArray): TwoStepSetup {
        val key = try {
            reauth.currentAuthKey(password)
        } finally {
            password.fill('\u0000')
        }
        return when (key) {
            is ReauthKey.Key -> postSetup(TotpSetupRequest(currentAuthKey = key.currentAuthKey))
            ReauthKey.Refused -> TwoStepSetup.NoSession
            ReauthKey.Unreachable -> TwoStepSetup.Unknown
            ReauthKey.WrongPassword -> TwoStepSetup.WrongPassword
        }
    }

    /**
     * The code alone no longer replaces the secret of an enrolled account (decided on 2026-11-16: the server asks for the
     * master password first). Kept so that no caller breaks: it sends nothing and answers [TwoStepSetup.ReauthRequired].
     * Use the overload that takes the password.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun rotate(code: String): TwoStepSetup = TwoStepSetup.ReauthRequired

    /**
     * A new secret for an enrolled account, authorised by its current [code] and the master [password] (wiped on every
     * path). A code that is not six digits is answered here, and nothing is derived or sent. The proof is derived behind
     * [Reauth]'s gate, so it goes to the session's own origin only.
     */
    suspend fun rotate(code: String, password: CharArray): TwoStepSetup {
        try {
            if (!isCode(code)) return TwoStepSetup.BadCode
            return when (val key = reauth.currentAuthKey(password)) {
                is ReauthKey.Key -> postSetup(TotpSetupRequest(code = code, currentAuthKey = key.currentAuthKey))
                ReauthKey.Refused -> TwoStepSetup.NoSession
                ReauthKey.Unreachable -> TwoStepSetup.Unknown
                ReauthKey.WrongPassword -> TwoStepSetup.WrongPassword
            }
        } finally {
            password.fill('\u0000')
        }
    }

    private suspend fun postSetup(body: TotpSetupRequest): TwoStepSetup {
        val r = client.call(WireRoute.TOTP_SETUP, bodyJson = WireJson.json.encodeToString(TotpSetupRequest.serializer(), body),
            decode = { WireJson.json.decodeFromString(TotpSetupResponse.serializer(), it) })
        return when (r) {
            is WireResult.Ok ->
                if (r.value.secretBase32.isEmpty() || !r.value.otpauthUri.startsWith("otpauth://")) TwoStepSetup.Unknown
                // The label names the account the secret is for: before a screen is given anything, it must name the
                // account this setup is for, under the product's own issuer. Another account's (another server's real
                // answer, or a label that cannot be read) is the server's fault, and nothing of it is shown.
                else if (labelAccount(r.value.otpauthUri) != reauth.emailNorm) TwoStepSetup.Refused(LABEL_NOT_THIS_ACCOUNT)
                else TwoStepSetup.Ready(TwoStepSecret(r.value.secretBase32, r.value.otpauthUri))
            is WireResult.Refused -> when {
                r.code == REAUTH_FAILED -> TwoStepSetup.Refused(Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
                r.code == REAUTH_REQUIRED -> TwoStepSetup.ReauthRequired
                r.code == WireErrors.BAD_TOTP_CODE -> TwoStepSetup.BadCode
                r.status >= 500 -> TwoStepSetup.Unknown
                else -> TwoStepSetup.Refused(r.code, r.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> TwoStepSetup.Unknown
        }
    }

    /** Ends a pending setup with a code from the authenticator. */
    suspend fun confirm(code: String): TwoStepAnswer = sendCode(WireRoute.TOTP_CONFIRM, code)

    /**
     * The code alone no longer turns two-step sign-in off (decided on 2026-11-16: the server asks for the master password
     * first). Kept so that no caller breaks: it sends nothing and answers [TwoStepAnswer.ReauthRequired]. Use the
     * overload that takes the password.
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun disable(code: String): TwoStepAnswer = TwoStepAnswer.ReauthRequired

    /**
     * Turns two-step sign-in off with a current [code] and the master [password] (wiped on every path); the server sends
     * the `two_step_off` email. A code that is not six digits is answered here, and nothing is derived or sent. The proof
     * is derived behind [Reauth]'s gate. The server checks the proof first, then its back-off for codes, then the code:
     * a wrong password caught here is [TwoStepAnswer.WrongPassword] with nothing sent; the server's `reauth_failed` is
     * [TwoStepAnswer.Refused] with [Reauthed.PROOF_REFUSED]; either back-off's `429` is [TwoStepAnswer.Refused] with its wait.
     */
    suspend fun disable(code: String, password: CharArray): TwoStepAnswer {
        try {
            if (!isCode(code)) return TwoStepAnswer.BadCode
            val key = when (val k = reauth.currentAuthKey(password)) {
                is ReauthKey.Key -> k.currentAuthKey
                ReauthKey.Refused -> return TwoStepAnswer.NoSession
                ReauthKey.Unreachable -> return TwoStepAnswer.Unknown
                ReauthKey.WrongPassword -> return TwoStepAnswer.WrongPassword
            }
            val body = WireJson.json.encodeToString(TotpDisableRequest.serializer(), TotpDisableRequest(code, key))
            return answerOf(client.call(WireRoute.TOTP_DISABLE, bodyJson = body, decode = { }))
        } finally {
            password.fill('\u0000')
        }
    }

    private suspend fun sendCode(route: WireRoute, code: String): TwoStepAnswer {
        if (!isCode(code)) return TwoStepAnswer.BadCode
        if (!reauth.proceeds()) return TwoStepAnswer.NoSession
        return answerOf(client.call(route, bodyJson = WireJson.json.encodeToString(TotpCodeRequest.serializer(), TotpCodeRequest(code)), decode = { }))
    }

    private fun answerOf(r: WireResult<Unit>): TwoStepAnswer {
        return when (r) {
            is WireResult.Ok -> TwoStepAnswer.Ok
            is WireResult.Refused -> when {
                // The server's refusal of the proof, never a wrong password typed here (that one is caught before anything is sent).
                r.code == REAUTH_FAILED -> TwoStepAnswer.Refused(Reauthed.PROOF_REFUSED, r.retryAfterSeconds)
                r.code == REAUTH_REQUIRED -> TwoStepAnswer.ReauthRequired
                r.code == WireErrors.BAD_TOTP_CODE -> TwoStepAnswer.BadCode
                r.code == WireErrors.NO_PENDING_TOTP -> TwoStepAnswer.NoPendingSetup
                r.code == WireErrors.TOTP_NOT_ENROLLED -> TwoStepAnswer.NotEnrolled
                r.status >= 500 -> TwoStepAnswer.Unknown
                else -> TwoStepAnswer.Refused(r.code, r.retryAfterSeconds)
            }
            is WireResult.NoAnswer -> TwoStepAnswer.Unknown
        }
    }

    private fun isCode(code: String) = code.length == 6 && code.all { it in '0'..'9' }

    companion object {
        private const val REAUTH_FAILED = "reauth_failed"
        private const val REAUTH_REQUIRED = "reauth_required"

        /**
         * A setup's answer whose `otpauth` label does not name the account it was asked for ([TwoStepSetup.Refused]): the
         * server's fault. Nothing of the answer is shown; the server may hold a pending setup that no code will confirm.
         */
        const val LABEL_NOT_THIS_ACCOUNT = "label_not_this_account"

        /** The issuer the server names in every label (`otpauth://totp/andvari:<address>?…&issuer=andvari`, spec 03 §2). */
        private const val ISSUER = "andvari"

        /**
         * The normalised address an `otpauth://totp/` URI's label names under [ISSUER], or null when it names none this
         * device can read: another issuer in the label or in an `issuer` parameter, no `issuer:` prefix, a percent
         * escape that does not decode, or an address outside the grammar.
         */
        internal fun labelAccount(uri: String): String? {
            val prefix = "otpauth://totp/"
            if (!uri.startsWith(prefix)) return null
            val rest = uri.substring(prefix.length)
            val q = rest.indexOf('?')
            val label = percentDecoded(if (q < 0) rest else rest.substring(0, q)) ?: return null
            val colon = label.indexOf(':')
            if (colon <= 0 || label.substring(0, colon) != ISSUER) return null
            if (q >= 0) {
                for (param in rest.substring(q + 1).split('&')) {
                    if (!param.startsWith("issuer=")) continue
                    if (percentDecoded(param.substring("issuer=".length)) != ISSUER) return null
                }
            }
            return io.silencelen.andvari.core.trust.TrustGrammar.emailNorm(label.substring(colon + 1).trim())
        }

        /** [s] with its `%XX` escapes decoded as UTF-8; null when an escape is broken or the bytes are not UTF-8. */
        private fun percentDecoded(s: String): String? {
            if ('%' !in s) return s
            val out = ArrayList<Byte>()
            var i = 0
            while (i < s.length) {
                val c = s[i]
                if (c == '%') {
                    if (i + 2 >= s.length) return null
                    val hi = s[i + 1].digitToIntOrNull(16) ?: return null
                    val lo = s[i + 2].digitToIntOrNull(16) ?: return null
                    out += ((hi shl 4) or lo).toByte()
                    i += 3
                } else {
                    val end = s.indexOf('%', i).let { if (it < 0) s.length else it }
                    s.substring(i, end).encodeToByteArray().forEach { out += it }
                    i = end
                }
            }
            return try {
                out.toByteArray().decodeToString(throwOnInvalidSequence = true)
            } catch (e: CharacterCodingException) {
                null
            }
        }
    }
}
