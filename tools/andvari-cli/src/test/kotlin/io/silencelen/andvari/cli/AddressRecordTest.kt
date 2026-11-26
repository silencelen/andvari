package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.server.queryOne
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The tool's lasting record of which account an address is at a server ([Host.CLI_ADDRESS]), over the real server. It
 * outlives a sign-out and the server's end of a session, so another account under a known address is refused with both
 * possibilities and the offer on every road, the sign-in's included; the same account under another key is refused with
 * no offer. Before, the tool's only tie was its saved session, which goes at both, and the sign-in took the other account
 * without a word.
 */
class AddressRecordTest {
    private val newPw: (String) -> String? = { when (it) { "ANDVARI_PASSWORD" -> Steps.PASSWORD; "ANDVARI_NEW_PASSWORD" -> "a brand new master password 77"; else -> null } }

    /** [email] made and signed in on [home]; answers its user id. */
    private fun made(w: CliWorld, home: File, email: String, kit: File): String {
        w.s.advance(2 * 3_600_000L)
        w.run(home, "enrol", Steps.enrolLink(w.s, email), "--email", email, "--kit-out", kit.path, "--trust-card", w.card0).ok()
        w.run(home, "sign-in", "--trust-card", w.card0).ok()
        return w.userId(email)
    }

    /** [email]'s account deleted from a home of its own and made again on another: answers the new id. */
    private fun remade(w: CliWorld, email: String): String {
        val b = File(w.tmp, "elsewhere-$email")
        w.run(b, "sign-in", "--email", email, "--trust-card", w.card0).ok()
        w.run(b, "account", "delete", "--confirm-email", email).ok()
        return made(w, File(w.tmp, "remade-$email"), email, File(w.tmp, "kit-remade-$email"))
    }

    private fun liveSessions(s: TestServer, userId: String): Long = s.services.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?",
            userId, s.now()) { it.getLong(1) }
    } ?: 0L

    /**
     * After a sign-out (which keeps the record), the account under the address is deleted and made again elsewhere: the
     * sign-in here is refused with both possibilities and the offer, the session the server opened is ended, and nothing
     * is kept. The forgetting then takes the new account at the next sign-in, said once.
     */
    @Test fun aSignInAfterASignOutUnderAnAddressServedAsAnotherAccountIsRefusedWithTheOffer() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "out@example.org"
            val a = File(w.tmp, "a")
            val u = made(w, a, me, File(w.tmp, "kit-u"))
            w.run(a, "sign-out", "--email", me).ok()
            assertEquals(u, CliHome(a).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$me"), "the record outlives the sign-out")
            val v = remade(w, me)
            val sessionsBefore = liveSessions(s, v)

            val r = w.run(a, "sign-in", "--email", me, "--trust-card", w.card0)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_OPENED, s.origin, me, ACT_SIGN_IN)), r.err)
            assertNull(CliHome(a).secureState().get("cli.session|${s.origin}|$me"), "nothing kept")
            assertEquals(sessionsBefore, liveSessions(s, v), "the session the server opened for this home is ended")

            val plan = w.run(a, "forget-earlier-account", "--email", me)
            assertEquals(2, plan.code, plan.out + plan.err)
            assertTrue(plan.err.lines().contains("  ${Host.CLI_ADDRESS}${s.origin}|$me"), plan.err)
            w.run(a, "forget-earlier-account", "--email", me, "--yes").ok()
            val taken = w.run(a, "sign-in", "--email", me, "--trust-card", w.card0)
            assertEquals(0, taken.code, taken.out + taken.err)
            assertEquals(1, taken.err.split(fill(NEW_ACCOUNT_REMEMBERED, s.origin, me)).size - 1, taken.err)
            assertEquals(v, CliHome(a).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$me"), "the address is the new account now")
        }
    }

    /**
     * The server ends this home's session (the account is deleted elsewhere, which ends its sessions): the next command
     * finds it ended, and the saved session goes; the record stays. The account made again under the address is refused at
     * the sign-in, with the offer; and at a recovery with its kit, before anything is sent.
     */
    @Test fun aSignInAndARecoveryAfterTheServerEndedTheSessionAreRefusedWithTheOffer() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "ended@example.org"
            val a = File(w.tmp, "a")
            val u = made(w, a, me, File(w.tmp, "kit-u"))
            remade(w, me)
            val ended = w.run(a, "sync")
            assertEquals(1, ended.code, ended.out + ended.err)
            assertNull(CliHome(a).secureState().get("cli.session|${s.origin}|$me"), "the server ended the session")
            assertEquals(u, CliHome(a).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$me"), "the record outlives the server's end")

            val r = w.run(a, "sign-in", "--email", me, "--trust-card", w.card0)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_OPENED, s.origin, me, ACT_SIGN_IN)), r.err)
            val out = File(w.tmp, "kit-new")
            val rec = w.run(a, "recover", "kit", "--kit-file", File(w.tmp, "kit-remade-$me").path, "--kit-out", out.path, origin = null, env = newPw)
            assertEquals(1, rec.code, rec.out + rec.err)
            assertTrue(rec.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED, s.origin, me, ACT_RECOVERY)), rec.err)
            assertFalse(out.exists(), "nothing committed")
        }
    }

    /**
     * The same account under another key after a sign-out (here: the home's record of the key is another key than the
     * server gives): refused at the sign-in and at a recovery with the kit, with no offer.
     */
    @Test fun theSameAccountUnderAnotherKeyAfterASignOutIsRefusedWithNoOffer() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "samekey@example.org"
            val a = File(w.tmp, "a")
            val kit = File(w.tmp, "kit-u")
            val u = made(w, a, me, kit)
            w.run(a, "sign-out", "--email", me).ok()
            CliHome(a).deviceState().set("${Host.CLI_IDENTITY}${s.origin}|$u", Bytes.toB64(createCryptoProvider().randomBytes(32)))
            val r = w.run(a, "sign-in", "--email", me, "--trust-card", w.card0)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: " + fill(IDENTITY_KEY_REFUSED_OPEN, s.origin, ACT_SIGN_IN)), r.err)
            val out = File(w.tmp, "kit-new")
            val rec = w.run(a, "recover", "kit", "--kit-file", kit.path, "--kit-out", out.path, origin = null, env = newPw)
            assertEquals(1, rec.code, rec.out + rec.err)
            assertTrue(rec.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: " + fill(IDENTITY_KEY_REFUSED, s.origin, ACT_RECOVERY)), rec.err)
            assertFalse(out.exists())
            for (f in listOf(r, rec)) assertFalse(f.err.contains("forget-earlier-account"), f.err)
            val forget = w.run(a, "forget-earlier-account", "--email", me)
            assertEquals(1, forget.code, forget.out + forget.err)
            assertTrue(forget.err.contains("[$KEY_EARLIER_NOT_OFFERED]: "), forget.err)
        }
    }

    /**
     * After a sign-out the person's own new account under the address is refused before anything is sent (the record),
     * with the offer; after the forgetting, the earlier account served again under a key of the server's own (here: the
     * record of its key is another) is refused with no offer; under its own key it is taken as itself.
     */
    @Test fun afterTheForgettingTheEarlierAccountUnderAnotherKeyIsRefusedAndUnderItsOwnTaken() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = "again@example.org"
            val a = File(w.tmp, "a")
            val kit = File(w.tmp, "kit-u")
            val u = made(w, a, me, kit)
            w.run(a, "sign-out", "--email", me).ok()
            s.advance(2 * 3_600_000L)
            val reg = w.run(a, "enrol", Steps.enrolLink(s, me), "--email", me, "--kit-out", File(w.tmp, "kit-v").path)
            assertEquals(1, reg.code, reg.out + reg.err)
            assertTrue(reg.err.contains("[$EARLIER_ACCOUNT_KNOWN]: " + fill(EARLIER_ACCOUNT_REFUSED_NEW, s.origin, me)), reg.err)
            w.run(a, "forget-earlier-account", "--email", me, "--yes").ok()
            assertNull(CliHome(a).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$me"), "the record goes with the forgetting")
            val keyRecord = "${Host.CLI_IDENTITY}${s.origin}|$u"
            val own = assertNotNull(CliHome(a).deviceState().get(keyRecord), "the key's record stays")

            CliHome(a).deviceState().set(keyRecord, Bytes.toB64(createCryptoProvider().randomBytes(32)))
            val r = w.run(a, "sign-in", "--email", me, "--trust-card", w.card0)
            assertEquals(1, r.code, r.out + r.err)
            assertTrue(r.err.contains("[$IDENTITY_KEY_NOT_KNOWN]: "), r.err)
            assertFalse(r.err.contains("forget-earlier-account"), r.err)

            CliHome(a).deviceState().set(keyRecord, own)
            val taken = w.run(a, "sign-in", "--email", me, "--trust-card", w.card0)
            assertEquals(0, taken.code, taken.out + taken.err)
            assertFalse(taken.err.contains(fill(NEW_ACCOUNT_REMEMBERED, s.origin, me)), "the same account, not a new one: ${taken.err}")
            assertEquals(u, CliHome(a).deviceState().get("${Host.CLI_ADDRESS}${s.origin}|$me"))
        }
    }
}
