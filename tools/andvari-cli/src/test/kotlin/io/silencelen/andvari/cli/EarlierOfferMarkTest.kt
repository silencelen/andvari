package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The offer's mark, the plan the forgetting prints, and the record of a key per server, over the real server. */
class EarlierOfferMarkTest {
    /**
     * The person's own registration under the address of the account this home keeps is refused with the offer. The plan
     * lists every record the forgetting would remove, one to a line. The account is then reopened (the server still serves
     * it): the offer is gone, and the command refuses as for an address never refused. Before, it forgot that account.
     */
    @Test fun anOfferDoesNotOutliveTheAccountItWasMadeAgainstAndThePlanListsEveryRecord() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "mark@example.org"
            val a = w.account(me)
            val u = w.userId(me)
            s.advance(2 * 3_600_000L)
            val r = w.run(a, "enrol", Steps.enrolLink(s, me), "--email", me, "--kit-out", File(w.tmp, "kit-2").path)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_NEW, s.origin, me)), r.err)
            val plan = w.run(a, "forget-earlier-account", "--email", me)
            assertEquals(2, plan.code, plan.out + plan.err)
            val h = CliHome(a)
            val goes = (h.deviceState().keys()!! + h.secureState().keys()!!).filter { k ->
                (u in k.split('|') && !k.startsWith(Host.CLI_IDENTITY)) || k == "cli.session|${s.origin}|$me" || k == "ovh.dev|${s.origin}|$me" ||
                    k == "cli.email|${s.origin}" || k == "${Host.CLI_EARLIER}${s.origin}|$me" || k == "${Host.CLI_ADDRESS}${s.origin}|$me"
            }.distinct()
            val listed = plan.err.lines().filter { it.startsWith("  ") }.map { it.trim() }
            assertEquals(goes.sorted(), listed.sorted(), plan.err)
            assertTrue(plan.err.contains("[$KEY_EARLIER_FORGET_PLAN]: " + fill(EARLIER_FORGET_PLAN, s.origin, me, u, goes.size)), plan.err)

            w.run(a, "sync").ok()
            val f = w.run(a, "forget-earlier-account", "--email", me, "--yes")
            assertEquals(1, f.code, f.out + f.err)
            assertTrue(f.err.contains("[$KEY_EARLIER_NOT_OFFERED]: " + fill(EARLIER_NOT_OFFERED, s.origin, me)), f.err)
            assertNotNull(h.secureState().get("cli.session|${s.origin}|$me"), "the account stays kept")
        }
    }

    /**
     * The record of a key is looked up for its own server: another server's record under the same account id does not
     * govern this one. Here the home has no record of the account's key at its server (a home from before the record) and
     * another server's record names that id with another key: the reopen goes on, and the home records the key it was
     * served at its own server. Before, the other server's record refused it.
     */
    @Test fun aRecordOfAKeyIsLookedUpForItsOwnServer() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "own@example.org"
            val a = w.account(me)
            val u = w.userId(me)
            val st = CliHome(a).deviceState()
            val own = "${Host.CLI_IDENTITY}${s.origin}|$u"
            val key = assertNotNull(st.get(own))
            st.set(own, null)
            st.set("${Host.CLI_IDENTITY}https://other.example|$u", Bytes.toB64(createCryptoProvider().randomBytes(32)))
            w.run(a, "sync").ok()
            assertEquals(key, st.get(own), "the key served at its own server is recorded there")
        }
    }
}
