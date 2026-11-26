package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.items.ItemNotice
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.server.HostCli
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.nio.file.Files
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * What a restore of the server's database from a backup does to the people who use it, right after the restore, over
 * the real server and real devices of the shared code. A restore is what the self-hosting guide tells an operator to do:
 * the nightly snapshot is taken with `VACUUM INTO` while the server runs, beside a copy of the blobs; later the server is
 * stopped, the snapshot is put back as its database (and the copy as its blobs), and the server is started again.
 *
 * These tests hold what the server and the devices do that is right: a device that saw a newer state refuses the older
 * one and applies nothing; a session renewed since the snapshot is unknown and ends without ending any other; the master
 * password in force is the one the backup holds. What a restore does wrong (a device that later skips other devices'
 * saves without a word; a device revoked since the snapshot that syncs again) is not pinned here as expected behaviour.
 */
class RestoreFromBackupTest {
    private val password get() = Steps.PASSWORD.toCharArray()
    private val newPassword get() = "a whole new Passphrase 42 here".toCharArray()

    /** A copy of the server's data as the guide's nightly backup takes it, while the server runs. */
    private class Backup(val db: File, val blobs: File)

    private fun World.backup(): Backup {
        val config = HostCli.configFrom(server.envFile)
        val dir = Files.createTempDirectory(server.dir.toPath(), "backup").toFile()
        val db = File(dir, "andvari.db")
        DriverManager.getConnection("jdbc:sqlite:${config.dbPath}").use { c ->
            c.createStatement().use { it.execute("VACUUM INTO '${db.path}'") }
        }
        val blobs = File(dir, "blobs").apply { mkdirs() }
        File(config.blobDir).takeIf { it.isDirectory }?.copyRecursively(blobs, overwrite = true)
        return Backup(db, blobs)
    }

    /** The server stops, the backup is put back as its database and blobs, and the server starts on them. */
    private fun World.restore(b: Backup) {
        val dir = Files.createTempDirectory(server.dir.toPath(), "restored").toFile()
        val db = b.db.copyTo(File(dir, "andvari.db"))
        val blobs = File(dir, "blobs").apply { mkdirs() }
        b.blobs.copyRecursively(blobs, overwrite = true)
        server.restart(mapOf("ANDVARI_DB" to db.path, "ANDVARI_BLOB_DIR" to blobs.path))
    }

    /** One authenticated call whose first answer is a 401, so the device renews its session once. */
    private suspend fun World.renew(h: Host) {
        val before = h.session(origin)!!.refreshToken
        val rule = proxy.on(WireRoute.ACCOUNT_KEYS, tag(h), times = 1) { _ -> Resp.error(401, "invalid_credentials") }
        h.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })
        rule.remove()
        assertTrue(h.session(origin)!!.refreshToken != before, "${tag(h)} renewed its session")
    }

    private fun names(items: List<io.silencelen.andvari.cli.PlainItem>): Set<String> =
        items.mapTo(HashSet()) { it.doc["name"]!!.jsonPrimitive.content }

    @Test fun afterARestoreEachDeviceThatSawNewerItemsRefusesTheOlderStateAndAppliesNothing() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        val b = account(passwordDevice("alice2", "alice@example.org"))
        val v = assertNotNull(a.personalVaultId)
        assertNull(a.putItem(v, doc("before")).second)
        a.synced()
        b.synced()
        val backup = backup()
        for (i in 1..3) assertNull(a.putItem(v, doc("after $i")).second)
        a.synced()
        b.synced()
        val newer = setOf("before", "after 1", "after 2", "after 3")
        assertEquals(newer, names(b.items(v)), "both devices hold the three saves made after the backup")

        restore(backup)

        for ((what, s) in listOf("the device that saved them" to a, "the device that synced them" to b)) {
            val held = s.items(v)
            assertEquals(SyncOutcome.Refused("rev_regression"), s.sync(), "$what: the older state is refused")
            assertTrue(s.items.notices().any { it.kind == ItemNotice.ROLLBACK }, "$what: the person is told once")
            assertEquals(held, s.items(v), "$what: nothing of the older state was applied and nothing was removed")
            assertEquals(newer, names(s.items(v)), what)
        }
        // A device that never saw the newer state reads only what the backup holds: the three saves are not on the server.
        val fresh = account(passwordDevice("alice3", "alice@example.org"))
        fresh.synced()
        assertEquals(setOf("before"), names(fresh.items(v)), "the server holds what the backup held")
    }

    @Test fun afterARestoreASessionRenewedSinceTheBackupEndsAsUnknownAndNoOtherSessionOfTheAccountEnds() = world {
        operator()
        val ah = member("alice")
        val renewed = passwordDevice("renewed", "alice@example.org")
        val renewedThenRevoked = passwordDevice("gone", "alice@example.org")
        val kept = passwordDevice("kept", "alice@example.org")
        for (h in listOf(ah, renewed, renewedThenRevoked, kept)) account(h).synced()
        val backup = backup()
        renew(renewed)
        renew(renewedThenRevoked)
        val goneId = renewedThenRevoked.session(origin)!!.session.deviceId
        assertIs<Reauthed.Done<*>>(ah.settings(ah.session(origin)!!).revoke(goneId, password), "the owner revokes a device that renewed")

        restore(backup)

        val mark = proxy.mark()
        for (h in listOf(renewed, renewedThenRevoked)) {
            account(h).sync()
            assertEquals(WireErrors.INVALID_REFRESH, h.endedByServer(origin)?.code, "${tag(h)}: its renewed token is unknown to the restored server")
            assertNull(h.session(origin), "${tag(h)}: signed out")
        }
        // The answers were "unknown", never the reuse of a consumed token: nothing ended the account's other sessions.
        val answers = proxy.since(mark).filter { it.req.route == WireRoute.REFRESH }.mapNotNull { it.upstream?.json?.get("error")?.jsonPrimitive?.content }
        assertTrue(WireErrors.REFRESH_REUSE !in answers, "no reuse alarm: $answers")
        for (h in listOf(ah, kept)) {
            account(h).synced()
            assertNull(h.endedByServer(origin), "${tag(h)}: still signed in")
        }
        // A device signed in at the backup that made no renewal since renews as before.
        renew(kept)
        account(kept).synced()
    }

    @Test fun afterARestoreTheMasterPasswordInForceIsTheOneTheBackupHolds() = world {
        operator()
        val ah = member("alice")
        account(ah).synced()
        val backup = backup()
        assertIs<Reauthed.Done<Unit>>(ah.changePassword(ah.session(origin)!!, password, newPassword), "the password is changed after the backup")

        restore(backup)

        val other = pinnedDevice("other")
        assertEquals(SignIn.InvalidCredentials, other.onboarding(origin).signIn("alice@example.org", newPassword), "the new password is refused")
        assertIs<SignIn.SignedIn>(other.onboarding(origin).signIn("alice@example.org", password), "the former password signs in")
    }
}
