package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * An account deleted elsewhere and made again under an address this home knows (decided on 2026-11-17), over the real
 * server. The tool ties an address to an account only by its saved session (`cli.session|<origin>|<email>`, with the
 * account's id), and keeps each account's identity key (`cli.identity|<origin>|<userId>`). Where a flow is served another
 * account id under the tied address, it stops with both possibilities and offers `forget-earlier-account`; where it is
 * served a known account under another key, it stops and offers nothing.
 */
class RemadeAccountTest {
    private val newPw: (String) -> String? = { when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null } }

    /** Every record of [home]'s two stores, by store and key. */
    private fun records(home: File): Map<String, String?> {
        val h = CliHome(home)
        return listOf("state" to h.deviceState(), "secure" to h.secureState()).flatMap { (n, st) -> st.keys()!!.map { "$n:$it" to st.get(it) } }.toMap()
    }

    /** [email] made on its own home [a] and signed in there; answers its user id. */
    private fun made(w: CliWorld, a: File, email: String, kit: File): String {
        w.s.advance(2 * 3_600_000L)
        w.run(a, "enrol", Steps.enrolLink(w.s, email), "--email", email, "--kit-out", kit.path, "--trust-card", w.card0).ok()
        w.run(a, "sign-in", "--trust-card", w.card0).ok()
        return w.userId(email)
    }

    /** [email]'s account deleted from another home, and made again on a third ([c]), signed in there: answers the new id. */
    private fun remade(w: CliWorld, email: String, c: File, kit: File): String {
        val b = File(w.tmp, "elsewhere-$email")
        w.run(b, "sign-in", "--email", email, "--trust-card", w.card0).ok()
        w.run(b, "account", "delete", "--confirm-email", email).ok()
        return made(w, c, email, kit)
    }

    @Test fun aRemadeAccountIsRefusedWithBothPossibilitiesAndForgottenOnlyAtTheSecondStep() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "me@example.org"
            val a = File(w.tmp, "a")
            val u = made(w, a, me, File(w.tmp, "kit-u"))
            val kitV = File(w.tmp, "kit-v")
            val v = remade(w, me, File(w.tmp, "c"), kitV)
            assertTrue(u != v)
            val out = File(w.tmp, "kit-new")

            val refused = w.run(a, "recover", "kit", "--kit-file", kitV.path, "--kit-out", out.path, origin = null, env = newPw)
            assertEquals(1, refused.code, refused.out + refused.err)
            assertTrue(refused.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED, s.origin, me, ACT_RECOVERY)), refused.err)
            assertFalse(out.exists(), "nothing committed")

            // The first step says what would go and changes nothing.
            val before = records(a)
            val tied = before.keys.filter { it.contains(u) || it.endsWith("|$me") }
            val plan = w.run(a, "forget-earlier-account", "--email", me)
            assertEquals(2, plan.code, plan.out + plan.err)
            assertEquals("", plan.out)
            val goes = before.keys.filter { k ->
                (k.contains(u) && !k.contains(Host.CLI_IDENTITY)) || k == "secure:cli.session|${s.origin}|$me" || k == "state:ovh.dev|${s.origin}|$me" ||
                    k == "state:cli.email|${s.origin}" || k == "state:${Host.CLI_EARLIER}${s.origin}|$me" || k == "state:${Host.CLI_ADDRESS}${s.origin}|$me"
            }
            assertTrue(plan.err.contains("[$KEY_EARLIER_FORGET_PLAN]: " + fill(EARLIER_FORGET_PLAN, s.origin, me, u, goes.size)), plan.err)
            for (k in goes) assertTrue(plan.err.lines().contains("  " + k.substringAfter(':')), "names $k on a line of its own: ${plan.err}")
            assertEquals(before, records(a), "the first step changed nothing")

            // The second step forgets exactly the earlier account; the server's records, the key record and the rest stay.
            val done = w.run(a, "forget-earlier-account", "--email", me, "--yes")
            assertTrue(done.ok().contains(fill(EARLIER_FORGOTTEN, s.origin, me)), done.out)
            val after = records(a)
            assertEquals(listOf("state:${Host.CLI_IDENTITY}${s.origin}|$u"), after.keys.filter { it.contains(u) })
            assertEquals(before["state:${Host.CLI_IDENTITY}${s.origin}|$u"], after["state:${Host.CLI_IDENTITY}${s.origin}|$u"])
            for ((k, value) in before) if (k !in goes && !k.startsWith("state:cli.email|") && !k.startsWith("state:${Host.CLI_EARLIER}")) {
                assertEquals(value, after[k], "kept: $k")
            }
            assertTrue(tied.isNotEmpty())
            assertTrue(w.run(a, "whoami").ok().contains("server:  andvari"), "the pin stays")

            // The next recovery under the address is taken as new and said once.
            val taken = w.run(a, "recover", "kit", "--kit-file", kitV.path, "--kit-out", out.path, origin = null, env = newPw)
            assertTrue(taken.ok().contains("recovered: $me ($v)"), taken.out)
            assertEquals(1, taken.err.split(fill(NEW_ACCOUNT_REMEMBERED, s.origin, me)).size - 1, taken.err)
            val next = w.run(a, "sync")
            assertEquals(0, next.code, next.out + next.err)
            assertFalse(next.err.contains(fill(NEW_ACCOUNT_REMEMBERED, s.origin, me)), next.err)
            val again = w.run(a, "forget-earlier-account", "--email", me, "--yes")
            assertEquals(1, again.code, again.out + again.err)
            assertTrue(again.err.contains("[$KEY_EARLIER_NOT_OFFERED]: " + fill(EARLIER_NOT_OFFERED, s.origin, me)), again.err)
        }
    }

    /**
     * A forgetting stopped after its first write and its first deletion is finished by the next run of any command, before
     * anything else: nothing of the earlier account is left but its key record.
     */
    @Test fun aForgettingThatWasBegunIsFinishedByTheNextRun() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "half@example.org"
            val a = File(w.tmp, "a")
            val u = made(w, a, me, File(w.tmp, "kit-u"))
            val c = File(w.tmp, "c")
            remade(w, me, c, File(w.tmp, "kit-v"))
            // A device link from the remade account's device is refused the same way, before the pickup.
            val r = link(w, c, a)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_LINK, s.origin, me, ACT_LINK)), r.err)
            // What the forgetting writes first, and its first deletion, as a run stopped there leaves them.
            CliHome(a).deviceState().set("${Host.CLI_FORGETTING}${s.origin}|$me", u)
            CliHome(a).secureState().set("cli.session|${s.origin}|$me", null)
            assertTrue(records(a).keys.count { it.contains(u) } > 1)
            w.run(a, "whoami").ok()
            assertEquals(listOf("state:${Host.CLI_IDENTITY}${s.origin}|$u"), records(a).keys.filter { it.contains(u) })
            assertTrue(records(a).keys.none { it.contains(Host.CLI_FORGETTING) || it.contains(Host.CLI_EARLIER) })
        }
    }

    /**
     * The server serves the account this home knows under another identity key than the one it took (here, the home's
     * record of the key is another's): the recovery stops before anything is committed, nothing is offered, and the
     * forgetting refuses and changes nothing. Before, the tool kept no key and the recovery went through.
     */
    @Test fun theSameAccountUnderAnotherKeyIsRefusedAndNothingIsOffered() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "key@example.org"
            val a = File(w.tmp, "a")
            val kitU = File(w.tmp, "kit-u")
            val u = made(w, a, me, kitU)
            val keyRecord = "${Host.CLI_IDENTITY}${s.origin}|$u"
            assertNotNull(CliHome(a).deviceState().get(keyRecord), "the home keeps the account's key")
            CliHome(a).deviceState().set(keyRecord, Bytes.toB64(createCryptoProvider().randomBytes(32)))
            val out = File(w.tmp, "kit-new")
            val r = w.run(a, "recover", "kit", "--kit-file", kitU.path, "--kit-out", out.path, origin = null, env = newPw)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: " + fill(IDENTITY_KEY_REFUSED, s.origin, ACT_RECOVERY)), r.err)
            assertFalse(out.exists())
            assertFalse(r.err.contains("forget-earlier-account"), "nothing offered")
            val before = records(a)
            for (args in listOf(arrayOf("forget-earlier-account", "--email", me), arrayOf("forget-earlier-account", "--email", me, "--yes"))) {
                val f = w.run(a, *args)
                assertEquals(1, f.code, f.out + f.err)
                assertTrue(f.err.contains("[$KEY_EARLIER_NOT_OFFERED]: " + fill(EARLIER_KEY_NOT_OFFERED, s.origin, me)), f.err)
                assertEquals(before, records(a), "nothing forgotten")
            }
        }
    }

    private fun await(buf: ByteArrayOutputStream, re: Regex): String =
        Await.until("a line matching ${re.pattern}", 120_000, { "so far: $buf" }) { re.find(buf.toString())?.groupValues?.get(1) }

    /** `link-device show` on [shows] and `link-device` on [joins]: the joining run. */
    private fun link(w: CliWorld, shows: File, joins: File): CliRun {
        val shown = ByteArrayOutputStream()
        val joined = ByteArrayOutputStream()
        val shownEnv: (String) -> String? = { n ->
            when (n) {
                "ANDVARI_PASSWORD" -> Steps.PASSWORD
                "ANDVARI_DEVICE_CODE" -> await(joined, Regex("Type this code on your other device: ([0-9 ]+)"))
                else -> null
            }
        }
        val pool = Executors.newFixedThreadPool(2)
        try {
            val show = pool.submit<CliRun> { CliRun.run(w.s, shows, "link-device", "show", env = shownEnv, out = shown, captureErr = false) }
            val url = await(shown, Regex("(?m)^(\\S+://\\S+)$"))
            val linkFile = File(w.tmp, "device-link-${joins.name}.txt").also { it.writeText(url) }
            val joining = pool.submit<CliRun> { CliRun.run(w.s, joins, "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null, out = joined) }
            val r = joining.get(5, TimeUnit.MINUTES)
            show.get(5, TimeUnit.MINUTES)
            return r
        } finally {
            pool.shutdownNow()
        }
    }

    /**
     * After a forgetting of U (this home's registration of a new account under U's address was refused: the refusal comes
     * before anything is sent), the server serves U again under another key (the home's record of U's key is another's):
     * refused, nothing offered. Under U's own key: taken as U, with no notice of a new account.
     */
    @Test fun aForgottenAccountServedAgainIsTakenOnlyUnderItsOwnKey() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "u@example.org"
            val a = File(w.tmp, "a")
            val kitU = File(w.tmp, "kit-u")
            val u = made(w, a, me, kitU)
            // A registration of a new account under U's address from this home names another account id.
            s.advance(2 * 3_600_000L)
            val r = w.run(a, "enrol", Steps.enrolLink(s, me), "--email", me, "--kit-out", File(w.tmp, "kit-v").path)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_NEW, s.origin, me)), r.err)
            w.run(a, "forget-earlier-account", "--email", me, "--yes").ok()
            val keyRecord = "${Host.CLI_IDENTITY}${s.origin}|$u"
            val ownKey = assertNotNull(CliHome(a).deviceState().get(keyRecord), "the forgetting keeps U's key")

            // U served again, under another key than the one this home took.
            CliHome(a).deviceState().set(keyRecord, Bytes.toB64(createCryptoProvider().randomBytes(32)))
            val out = File(w.tmp, "kit-new")
            val refused = w.run(a, "recover", "kit", "--kit-file", kitU.path, "--kit-out", out.path, origin = null, env = newPw)
            assertEquals(1, refused.code, refused.out + refused.err)
            assertTrue(refused.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: "), refused.err)
            assertFalse(out.exists())
            assertTrue(w.run(a, "forget-earlier-account", "--email", me).err.contains(fill(EARLIER_KEY_NOT_OFFERED, s.origin, me)))

            // Under its own key: taken as U, and no new account is said.
            CliHome(a).deviceState().set(keyRecord, ownKey)
            val taken = w.run(a, "recover", "kit", "--kit-file", kitU.path, "--kit-out", out.path, origin = null, env = newPw)
            assertTrue(taken.ok().contains("recovered: $me ($u)"), taken.out + taken.err)
            assertFalse(taken.err.contains(fill(NEW_ACCOUNT_REMEMBERED, s.origin, me)), taken.err)
        }
    }
}
