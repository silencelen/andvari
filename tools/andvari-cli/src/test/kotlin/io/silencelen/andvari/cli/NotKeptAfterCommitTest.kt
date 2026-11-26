package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.queryOne
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A commit the server made while what this home keeps changed (another run kept another account at that server while
 * the commit was out): the home does not keep the new session, ends exactly that one at the real server, and the command
 * says the change happened, with the account's new kit kept (written, never confirmed). Before, the tool's sink kept every
 * session it was handed, so a second account was kept on the home beside the one it already kept.
 */
class NotKeptAfterCommitTest {
    private val newPw = "a whole new master password 4711"
    private fun pw(p: String): (String) -> String? = { if (it == "ANDVARI_PASSWORD") p else null }

    /** The account's sessions the server would still refresh. */
    private fun liveSessions(s: TestServer, userId: String): Long = s.services.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL AND refreshConsumedAt IS NULL AND refreshExpiresAt>?",
            userId, s.now()) { it.getLong(1) }
    } ?: 0L

    /**
     * While [route]'s request is at the server, [home] starts keeping bo: bo's session, signed in on a home of its own
     * beforehand, is written into [home]'s store. Another run of the tool cannot do that any more (a command holds its home
     * while it runs, [HomeLockTest]); this is a home changed from outside that lock, which the commit's own check still stops.
     */
    private fun boSignsInMeanwhile(p: LyingProxy, s: TestServer, w: CliWorld, route: WireRoute, home: File) =
        boKeptMeanwhile(p, s, w, route, home)

    companion object {
        /** [boSignsInMeanwhile], for every test of a commit under way while what the home keeps changes. */
        fun boKeptMeanwhile(p: LyingProxy, s: TestServer, w: CliWorld, route: WireRoute, home: File) {
            val elsewhere = File(w.tmp, "bo-elsewhere")
            w.run(elsewhere, "sign-in", "--email", "bo@example.org", "--trust-card", w.card0).ok()
            val key = "cli.session|${s.origin}|bo@example.org"
            val kept = CliHome(elsewhere).secureState().get(key)!!
            p.answer = mapOf(route to { _, forward ->
                val (status, text) = forward()
                assertEquals(200, status, "the server committed")
                CliHome(home).secureState().set(key, kept)
                status to String(text)
            })
        }
    }

    @Test fun aKitRecoveryCommittedWhileAnotherAccountWasKeptHereKeepsTheKitAndSaysTheRecoveryWentThrough() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                w.account("me@example.org")
                val bo = w.account("bo@example.org")
                val meId = w.userId("me@example.org")
                val d = File(w.tmp, "d")
                val kit = File(w.tmp, "me-new-kit.txt")
                boSignsInMeanwhile(p, s, w, WireRoute.RECOVERY_SELF_COMMIT, d)
                val r = w.run(d, "recover", "kit", "--kit-file", w.kit("me@example.org").path, "--kit-out", kit.path, origin = null, env = pw(newPw), dial = p.address)
                p.answer = emptyMap()
                assertEquals(1, r.code, r.out + r.err)
                val said = fill(RECOVERY_COMMITTED_NOT_KEPT, s.origin, "me@example.org", fill(COMMITTED_KIT_WRITTEN, kit.path),
                    fill(NOT_KEPT_ANOTHER, "bo@example.org"))
                assertTrue(r.err.contains("[$KEY_COMMITTED_NOT_KEPT]: $said"), r.err)
                assertTrue(kit.exists(), "the new kit is kept")
                assertEquals(0, liveSessions(s, meId), "the session this home did not keep is ended at the server")
                // What the sentence says is so: the new password is in force, the old kit is dead, the new kit works.
                w.run(File(w.tmp, "e"), "sign-in", "--email", "me@example.org", "--trust-card", w.card0, env = pw(newPw)).ok()
                val old = w.run(File(w.tmp, "f"), "recover", "kit", "--kit-file", w.kit("me@example.org").path, "--kit-out", File(w.tmp, "never.txt").path, origin = null, env = pw(newPw))
                assertTrue(old.err.contains(Commands.KIT_REJECTED), old.err)
                w.run(File(w.tmp, "g"), "recover", "kit", "--kit-file", kit.path, "--kit-out", File(w.tmp, "me-kit-3.txt").path, origin = null, env = pw(newPw)).ok()
                // Bo's session on that home stays.
                w.run(d, "item", "list", "personal", "--email", "bo@example.org").ok()
                w.run(bo, "item", "list", "personal").ok()
            }
        }
    }

    @Test fun aRegistrationMadeWhileAnotherAccountWasKeptHereKeepsTheKitAndSaysTheAccountWasMade() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                w.account("bo@example.org")
                val home = File(w.tmp, "new")
                val kit = File(w.tmp, "new-kit.txt")
                boSignsInMeanwhile(p, s, w, WireRoute.REGISTER, home)
                val r = w.run(home, "enrol", Steps.enrolLink(s, "new@example.org"), "--email", "new@example.org", "--kit-out", kit.path,
                    "--trust-card", w.card0, "--device-name", "new", dial = p.address)
                p.answer = emptyMap()
                assertEquals(1, r.code, r.out + r.err)
                val said = fill(REGISTRATION_COMMITTED_NOT_KEPT, s.origin, "new@example.org", fill(COMMITTED_KIT_WRITTEN, kit.path),
                    fill(NOT_KEPT_ANOTHER, "bo@example.org"))
                assertTrue(r.err.contains("[$KEY_COMMITTED_NOT_KEPT]: $said"), r.err)
                assertTrue(kit.exists(), "the kit is kept")
                val newId = w.userId("new@example.org")
                assertEquals(0, liveSessions(s, newId), "the session this home did not keep is ended at the server")
                // The account exists under the chosen password, and its kit is the one kept.
                w.run(File(w.tmp, "n2"), "sign-in", "--email", "new@example.org", "--trust-card", w.card0).ok()
                w.run(File(w.tmp, "n3"), "recover", "kit", "--kit-file", kit.path, "--kit-out", File(w.tmp, "new-kit-2.txt").path, origin = null, env = pw(newPw)).ok()
                w.run(home, "item", "list", "personal", "--email", "bo@example.org").ok()
            }
        }
    }
}
