package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A request for the operator's help kept under the address whose earlier account is forgotten: the plan lists it and says
 * why it goes; `--yes` removes it with the account, so nothing of it stays behind. Over the real server.
 */
class EarlierRequestTest {
    @Test fun aKeptRequestUnderTheAddressIsListedAndGoesWithTheForgetting() {
        val crypto = createCryptoProvider()
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey))).use { s ->
            val w = CliWorld(s)
            val me = "asked@example.org"
            val a = w.account(me)
            w.run(a, "recovery", "operator", "--i-understand").ok()
            val seen = Steps.mailCount(s, me, "recovery_request_code")
            w.run(a, "recover", "assist", "--email", me, "--trust-card", w.card0, stdin ={ Steps.awaitCode(s, me, "recovery_request_code", seen) }).ok()
            val request = "${Host.KEPT_ASSIST}${s.origin}"
            assertTrue(CliHome(a).secureState().get(request) != null, "the request is kept")

            s.advance(2 * 3_600_000L)
            val refused = w.run(a, "enrol", Steps.enrolLink(s, me), "--email", me, "--kit-out", File(w.tmp, "kit-2").path)
            assertEquals(1, refused.code, refused.out + refused.err)

            val plan = w.run(a, "forget-earlier-account", "--email", me)
            assertEquals(2, plan.code, plan.out + plan.err)
            assertTrue(plan.err.lines().contains("  $request"), plan.err)
            assertTrue(plan.err.contains(fill(EARLIER_PLAN_REQUEST, s.origin, me)), plan.err)
            assertTrue(CliHome(a).secureState().get(request) != null, "the plan changed nothing")

            val done = w.run(a, "forget-earlier-account", "--email", me, "--yes")
            assertEquals(0, done.code, done.out + done.err)
            assertTrue(done.out.contains(fill(EARLIER_REQUEST_FORGOTTEN, s.origin, me)), done.out)
            assertNull(CliHome(a).secureState().get(request), "nothing of the request stays")
            val after = w.run(a, "recover", "assist")
            assertEquals(2, after.code, after.out + after.err)
            assertTrue(after.err.contains("no request is kept for ${s.origin} on this device"), after.err)
        }
    }
}
