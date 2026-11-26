package io.silencelen.andvari.core.client.account

import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.model.wire.TotpCodeRequest
import io.silencelen.andvari.core.model.wire.TotpDisableRequest
import io.silencelen.andvari.core.model.wire.TotpSetupRequest
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Two-step sign-in in Settings (spec 03 rows 13 to 16) against a scripted server. */
class TwoStepTest {
    private val origin = "https://home.example"

    private class Sent(val route: WireRoute, val body: String?)

    private inner class Server : WireClient {
        override val origin = this@TwoStepTest.origin
        val sent = ArrayList<Sent>()
        var answer: (WireRoute, String?) -> WireResult<String> = { _, _ -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT) }
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            sent += Sent(route, bodyJson)
            return when (val a = answer(route, bodyJson)) {
                is WireResult.Ok -> WireResult.Ok(decode(a.value), a.status)
                is WireResult.Refused -> a
                is WireResult.NoAnswer -> a
            }
        }
    }

    private fun refused(status: Int, code: String) = WireResult.Refused(status, WireError(code, "m"))

    private class Env(val server: Server, val twoStep: WireTwoStep, val pins: MutableList<GatePin>)

    private fun env(): Env {
        val server = Server()
        val pins = mutableListOf(GatePin(origin, PinRoot.TRUST_GATE))
        val reauth = Reauth(object : ReauthSession {
            override val origin = this@TwoStepTest.origin
            override val emailNorm = "alice@example.com"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String? = "key-of-" + password.concatToString()
        }) { pins }
        return Env(server, WireTwoStep(server, reauth), pins)
    }

    @Test fun statusSetupConfirmAndDisable() = runBlocking<Unit> {
        val e = env()
        e.server.answer = { route, body ->
            when (route) {
                WireRoute.TOTP_STATUS -> WireResult.Ok("{\"enrolled\":false,\"pendingSetup\":false}", 200)
                WireRoute.TOTP_SETUP -> WireResult.Ok("{\"secretBase32\":\"JBSWY3DPEHPK3PXP\",\"otpauthUri\":\"otpauth://totp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari\"}", 200)
                WireRoute.TOTP_CONFIRM ->
                    if (WireJson.json.decodeFromString(TotpCodeRequest.serializer(), body!!).code == "123456") WireResult.Ok("", 200) else refused(400, "bad_totp_code")
                // The server's order since 2026-11-16: the proof first, then the code.
                WireRoute.TOTP_DISABLE -> {
                    val b = WireJson.json.decodeFromString(TotpDisableRequest.serializer(), body!!)
                    when {
                        b.currentAuthKey != "key-of-pw" -> refused(403, "reauth_failed")
                        b.code != "123456" -> refused(400, "bad_totp_code")
                        else -> WireResult.Ok("", 200)
                    }
                }
                else -> error("unexpected $route")
            }
        }
        assertEquals(Fetched.Ok(TwoStepStatus(enrolled = false, pendingSetup = false)), e.twoStep.status())
        val password = "pw".toCharArray()
        val ready = assertIs<TwoStepSetup.Ready>(e.twoStep.setup(password))
        assertTrue(password.all { it == '\u0000' }, "the password is wiped")
        assertEquals("JBSWY3DPEHPK3PXP", ready.secret.secretBase32)
        val setupBody = WireJson.json.decodeFromString(TotpSetupRequest.serializer(), e.server.sent.last().body!!)
        assertEquals("key-of-pw", setupBody.currentAuthKey)
        assertNull(setupBody.code)
        assertEquals(TwoStepAnswer.BadCode, e.twoStep.confirm("654321"))
        assertEquals(TwoStepAnswer.Ok, e.twoStep.confirm("123456"))
        // The code alone sends nothing and says the password is needed.
        val before = e.server.sent.size
        assertEquals(TwoStepAnswer.ReauthRequired, e.twoStep.disable("123456"))
        assertEquals(TwoStepSetup.ReauthRequired, e.twoStep.rotate("123456"))
        assertEquals(before, e.server.sent.size, "nothing is sent for a code alone")
        // With the password: its proof beside the code, and the password wiped on every path.
        val wrong = "nope".toCharArray()
        assertEquals(TwoStepAnswer.Refused(Reauthed.PROOF_REFUSED), e.twoStep.disable("123456", wrong), "the server's refusal of the proof")
        assertTrue(wrong.all { it == '\u0000' }, "wiped after a refusal")
        val badCode = "pw".toCharArray()
        assertEquals(TwoStepAnswer.BadCode, e.twoStep.disable("654321", badCode))
        assertTrue(badCode.all { it == '\u0000' })
        val pw = "pw".toCharArray()
        assertEquals(TwoStepAnswer.Ok, e.twoStep.disable("123456", pw))
        assertTrue(pw.all { it == '\u0000' })
        assertEquals(WireRoute.TOTP_DISABLE, e.server.sent.last().route)
        val disableBody = WireJson.json.decodeFromString(TotpDisableRequest.serializer(), e.server.sent.last().body!!)
        assertEquals("key-of-pw", disableBody.currentAuthKey)
        assertEquals("123456", disableBody.code)
    }

    /**
     * The setup's answer names the account its secret is for, in its `otpauth` label: it must name the account this setup
     * is for, under the product's issuer, before a screen is given anything. Before, an answer naming another account (a
     * server passing on another account's real answer) was shown as served, and a code typed from it set nothing up.
     */
    @Test fun aSetupWhoseLabelNamesAnotherAccountIsTheServersFaultAndShowsNothing() = runBlocking<Unit> {
        val e = env()
        var uri = ""
        e.server.answer = { route, _ ->
            if (route != WireRoute.TOTP_SETUP) error("unexpected $route")
            WireResult.Ok("{\"secretBase32\":\"JBSWY3DPEHPK3PXP\",\"otpauthUri\":\"$uri\"}", 200)
        }
        for (other in listOf(
            "otpauth://totp/andvari:bob@example.org?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
            "otpauth://totp/andvari:alice@example.org?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
            "otpauth://totp/andvari:alice?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
            "otpauth://totp/alice@example.com?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/other:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=other",
            "otpauth://totp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=other",
            "otpauth://totp/andvari:alice%4?secret=JBSWY3DPEHPK3PXP",
            "otpauth://hotp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP",
        )) {
            uri = other
            assertEquals(TwoStepSetup.Refused(WireTwoStep.LABEL_NOT_THIS_ACCOUNT), e.twoStep.setup("pw".toCharArray()), other)
            assertEquals(TwoStepSetup.Refused(WireTwoStep.LABEL_NOT_THIS_ACCOUNT), e.twoStep.rotate("111111", "pw".toCharArray()), other)
        }
        // This account's own label, as the server writes it and in other spellings of the same address.
        for (own in listOf(
            "otpauth://totp/andvari:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari&algorithm=SHA1&digits=6&period=30",
            "otpauth://totp/andvari:Alice@Example.com?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/andvari%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=andvari",
        )) {
            uri = own
            assertIs<TwoStepSetup.Ready>(e.twoStep.setup("pw".toCharArray()), own)
        }
    }

    @Test fun everyRefusalOfTheTableIsItsOwnAnswer() = runBlocking<Unit> {
        val e = env()
        var setupAnswer: WireResult<String> = refused(403, "reauth_failed")
        var codeAnswer: WireResult<String> = refused(400, "no_pending_totp")
        e.server.answer = { route, _ -> if (route == WireRoute.TOTP_SETUP) setupAnswer else codeAnswer }
        // The server's refusal of the proof is its own result, never a wrong password typed here.
        assertEquals(TwoStepSetup.Refused(Reauthed.PROOF_REFUSED), e.twoStep.setup("pw".toCharArray()))
        setupAnswer = refused(403, "reauth_required")
        assertEquals(TwoStepSetup.ReauthRequired, e.twoStep.setup("pw".toCharArray()))
        setupAnswer = refused(400, "bad_totp_code")
        assertEquals(TwoStepSetup.BadCode, e.twoStep.rotate("111111", "pw".toCharArray()))
        val rotateBody = WireJson.json.decodeFromString(TotpSetupRequest.serializer(), e.server.sent.last().body!!)
        assertEquals("111111", rotateBody.code)
        assertEquals("key-of-pw", rotateBody.currentAuthKey, "a rotation carries the password's proof too")
        setupAnswer = refused(403, "reauth_failed")
        assertEquals(TwoStepSetup.Refused(Reauthed.PROOF_REFUSED), e.twoStep.rotate("111111", "pw".toCharArray()), "the server's refusal of the proof")
        setupAnswer = refused(429, "rate_limited")
        assertEquals(TwoStepSetup.Refused("rate_limited"), e.twoStep.rotate("111111", "pw".toCharArray()))
        setupAnswer = refused(429, "rate_limited")
        assertEquals(TwoStepSetup.Refused("rate_limited"), e.twoStep.setup("pw".toCharArray()))
        setupAnswer = WireResult.Ok("{\"secretBase32\":\"\",\"otpauthUri\":\"x\"}", 200)
        assertEquals(TwoStepSetup.Unknown, e.twoStep.setup("pw".toCharArray()), "an answer with no usable secret is not a setup")
        assertEquals(TwoStepAnswer.NoPendingSetup, e.twoStep.confirm("123456"))
        codeAnswer = refused(400, "totp_not_enrolled")
        assertEquals(TwoStepAnswer.NotEnrolled, e.twoStep.disable("123456", "pw".toCharArray()))
        codeAnswer = refused(403, "reauth_failed")
        assertEquals(TwoStepAnswer.Refused(Reauthed.PROOF_REFUSED), e.twoStep.disable("123456", "pw".toCharArray()), "turning it off: the server's refusal of the proof")
        codeAnswer = refused(403, "reauth_required")
        assertEquals(TwoStepAnswer.ReauthRequired, e.twoStep.disable("123456", "pw".toCharArray()))
        // Either back-off (the proofs' or the codes') is a 429 with its wait.
        codeAnswer = WireResult.Refused(429, WireError("rate_limited", "m"), retryAfterSeconds = 60)
        assertEquals(TwoStepAnswer.Refused("rate_limited", 60), e.twoStep.disable("123456", "pw".toCharArray()))
        codeAnswer = refused(503, "unavailable")
        assertEquals(TwoStepAnswer.Unknown, e.twoStep.disable("123456", "pw".toCharArray()))
        codeAnswer = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        assertEquals(TwoStepAnswer.Unknown, e.twoStep.confirm("123456"))
    }

    @Test fun nothingIsSentWithoutTheGateOrWithAMalformedCode() = runBlocking<Unit> {
        val e = env()
        e.server.answer = { _, _ -> error("nothing may be sent") }
        assertEquals(TwoStepAnswer.BadCode, e.twoStep.confirm("12345"))
        val malformed = "pw".toCharArray()
        assertEquals(TwoStepAnswer.BadCode, e.twoStep.disable("12a456", malformed))
        assertTrue(malformed.all { it == '\u0000' }, "a malformed code: nothing derived, the password wiped")
        assertEquals(TwoStepSetup.BadCode, e.twoStep.rotate("1234567", "pw".toCharArray()))
        e.pins.clear()
        e.pins += GatePin(origin, PinRoot.TRUST_GATE, blocked = true)
        val password = "pw".toCharArray()
        assertEquals(TwoStepSetup.NoSession, e.twoStep.setup(password))
        assertTrue(password.all { it == '\u0000' })
        val rotating = "pw".toCharArray()
        assertEquals(TwoStepSetup.NoSession, e.twoStep.rotate("123456", rotating))
        assertTrue(rotating.all { it == '\u0000' })
        assertEquals(TwoStepAnswer.NoSession, e.twoStep.confirm("123456"))
        val disabling = "pw".toCharArray()
        assertEquals(TwoStepAnswer.NoSession, e.twoStep.disable("123456", disabling))
        assertTrue(disabling.all { it == '\u0000' })
        assertTrue(e.server.sent.isEmpty())
    }
}
