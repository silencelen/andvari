package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.account.Fetched
import io.silencelen.andvari.core.client.account.Reauthed
import io.silencelen.andvari.core.client.account.WireOperatorRoutes
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.RecoveryChoiceKind
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.client.recovery.AssistedStep
import io.silencelen.andvari.core.client.recovery.WireAssistedRecovery
import io.silencelen.andvari.core.trust.AnswerRead
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.core.client.state.RecoveryRecord
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.RecoveryRequestState
import io.silencelen.andvari.core.model.wire.RefreshRequest
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.server.Clock
import io.silencelen.andvari.server.HostCli
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * `andvari admin restored`, the command an operator runs once after putting a backup's files back and before starting
 * the server: over the real server's database and over the real server with real devices of the shared code. A restore is
 * done as the self-hosting guide says ([restoreFrom]); the command runs on the put-back files while no server has them.
 */
class RestoredStartTest {
    private val crypto = createCryptoProvider()
    private val email = "alice@example.org"
    private val password get() = Steps.PASSWORD.toCharArray()
    private val newPassword get() = "a whole new Passphrase 42 here".toCharArray()

    /** The key of the command's record in the server's own settings (`meta`). */
    private val recordKey = "restoredStart"

    private fun <T> db(env: File, block: (Connection) -> T): T =
        DriverManager.getConnection("jdbc:sqlite:${HostCli.configFrom(env).dbPath}").use(block)

    private fun <T> open(path: String, block: (Connection) -> T): T = DriverManager.getConnection("jdbc:sqlite:$path").use(block)

    private fun Connection.long(sql: String, vararg args: Any?): Long = prepareStatement(sql).use { st ->
        args.forEachIndexed { i, a -> st.setObject(i + 1, a) }
        st.executeQuery().use { rs -> if (rs.next()) rs.getLong(1) else 0L }
    }

    private fun Connection.text(sql: String): String = createStatement().use { st ->
        st.executeQuery(sql).use { rs -> buildList { while (rs.next()) add(rs.getString(1)) }.joinToString(",") }
    }

    private fun Connection.tables(): List<String> = createStatement().use { st ->
        st.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").use { rs ->
            buildList { while (rs.next()) add(rs.getString(1)) }
        }
    }

    private fun Connection.rowCounts(): Map<String, Long> = tables().associateWith { long("SELECT COUNT(*) FROM \"$it\"") }

    /** Every row of [table], in a fixed order, as text: what "changed nothing in it" compares. The command's record is left out of `meta`. */
    private fun Connection.rows(table: String): List<String> = createStatement().use { st ->
        st.executeQuery("SELECT * FROM \"$table\"").use { rs ->
            val n = rs.metaData.columnCount
            buildList { while (rs.next()) add((1..n).joinToString("|") { rs.getString(it) ?: "∅" }) }
                .filterNot { table == "meta" && it.startsWith("$recordKey|") }
                .sorted()
        }
    }

    private fun Connection.exec(sql: String, vararg args: Any?) = prepareStatement(sql).use { st ->
        args.forEachIndexed { i, a -> st.setObject(i + 1, a) }
        st.executeUpdate()
    }

    private fun record(env: File): String? = db(env) { c ->
        c.prepareStatement("SELECT value FROM meta WHERE key=?").use { st ->
            st.setString(1, recordKey)
            st.executeQuery().use { rs -> if (rs.next()) rs.getString(1) else null }
        }
    }

    private fun sha(f: File): String = MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }

    /**
     * The content and the settings of every account, the instance's identity, the audit, the retention fence, the change
     * counter's rows and the requests for the operator's help.
     */
    private val untouched = listOf(
        "users", "member_recovery", "escrow", "account_state", "personal_wrap", "usage_ledger", "vaults", "vault_log", "grants",
        "items", "item_versions", "attachments", "connections", "instance_setup", "instance_cards", "recovery_rotations", "audit",
        "policies", "meta", "mutations", "session_chains", "retired_ids", "changes",
    )

    /**
     * The columns of `recovery_requests` the command may change, and only on rows of an account: `state`, `codeMac`,
     * `sealed`, `commitHash` (a request past its mailed code: ended as refused, the answer dropped) and `cancelledAt` (one
     * before it). Every other column of every row, and every column of a decoy's row, stays as it was.
     */
    private val requestColumnsTheCommandWrites = setOf("state", "codeMac", "sealed", "commitHash", "cancelledAt")

    /** Every row of `recovery_requests` without the columns the command may write, and the decoys' rows whole. */
    private fun Connection.requestRowsKept(): List<String> = createStatement().use { st ->
        st.executeQuery("SELECT * FROM recovery_requests").use { rs ->
            val md = rs.metaData
            buildList {
                while (rs.next()) {
                    val decoy = rs.getString("userId") == null
                    add((1..md.columnCount).filter { decoy || md.getColumnName(it) !in requestColumnsTheCommandWrites }
                        .joinToString("|") { "${md.getColumnName(it)}=${rs.getString(it) ?: "∅"}" })
                }
            }.sorted()
        }
    }

    /**
     * A sign-in again on [h] with [pw]: through the Trust Gate when the device asks for it first. The password is a new
     * array at each try, as a person types it again (a try wipes the array it was given).
     */
    private suspend fun World.signInAgain(h: Host, pw: CharArray = password, who: String = email): SignIn {
        val typed = pw.copyOf()
        val first = h.onboarding(origin).signIn(who, pw)
        if (first !is SignIn.TrustGateFirst) return first
        val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        assertIs<FirstPin.Pinned>(h.trust.confirmTrustGate(gate.confirm))
        return h.onboarding(origin).signIn(who, typed)
    }

    /** A device that keeps its copy at rest (as an app does), its person through the Trust Gate and signed in. */
    private suspend fun World.signedIn(name: String): Host = server.switchedDevice(name).also { h ->
        val gate = assertIs<FirstPin.NeedsTrustGate>(h.trust.beginTrustGate(origin, TrustGateWording.TYPED_ADDRESS))
        assertIs<FirstPin.Pinned>(h.trust.confirmTrustGate(gate.confirm))
        assertIs<SignIn.SignedIn>(h.onboarding(origin).signIn(email, password))
    }

    /** A copy of [s] put back in a new directory of its own, with an environment file naming it; [extra] runs on the directory first. */
    private fun World.putBack(s: Snapshot, label: String, extra: (File) -> Unit = {}): Pair<File, File> {
        val dir = Files.createTempDirectory(server.dir.toPath(), label).toFile()
        val db = s.db.copyTo(File(dir, "andvari.db"))
        val blobs = File(dir, "blobs").apply { mkdirs() }
        s.blobs.copyRecursively(blobs, overwrite = true)
        extra(dir)
        val env = File(dir, "andvari.env")
        env.writeText(server.envFile.readText())
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to db.path, "ANDVARI_BLOB_DIR" to blobs.path))
        return db to env
    }

    /** A Java process of its own on this test's class path, running [main] with [args]. */
    private fun javaChild(main: String, vararg args: String): ProcessBuilder {
        val java = File(System.getProperty("java.home"), "bin/java").path
        return ProcessBuilder(listOf(java, "-cp", System.getProperty("java.class.path"), main) + args).redirectErrorStream(true)
    }

    /** The operator's recovery key (its seed signs the operator's answers in these tests). */
    private val recoverySeed = crypto.randomBytes(32)

    private fun recoveryArgs() = listOf("--recovery-pubkey", Bytes.toB64(crypto.boxKeypairFromSeed(recoverySeed).publicKey))

    /** A requester's device asks the operator's help for Alice's account and enters the mailed code: the request waits in its hold. */
    private suspend fun World.asking(tag: String): Pair<Host, AssistedStep.Waiting> {
        val (d, requested, code) = requested(tag)
        return d to assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, code))
    }

    /** A requester's device asks the operator's help for Alice's account; the mailed code is read but not yet entered. */
    private suspend fun World.requested(tag: String): Triple<Host, AssistedStep.Requested, String> {
        val d = device(tag)
        val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start(email, origin))
        val seen = Steps.mailCount(server, email, "recovery_request_code")
        val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target))
        return Triple(d, requested, Steps.awaitCode(server, email, "recovery_request_code", seen))
    }

    /** The operator's answer to [row], signed with the recovery key, for Alice's account key [uvk]. */
    private fun answerFor(row: AdminRecoveryRequest, instanceId: String, uvk: ByteArray): AnswerRead.Ok {
        val commit = crypto.randomBytes(32)
        val fields = AssistedRecoveryFields(instanceId, row.userId, row.requestId, row.rPub, uvk, 1_800_000_000_000L, email = row.email, commit = commit)
        val sealed = AssistedRecovery.seal(crypto, Bytes.fromB64(row.rPub), AssistedRecovery.sign(crypto, crypto.signKeypairFromSeed(recoverySeed), fields))
        val token = AnswerToken.format(row.requestId, row.rPub, AssistedRecovery.commitHash(crypto, commit), sealed)
        return assertIs<AnswerRead.Ok>(AnswerToken.read(token, row.requestId, row.rPub, row.email))
    }

    private suspend fun World.optIn(h: Host): RecoveryRecord {
        val s = h.recoverySettings(h.session(origin)!!)
        return assertIs<Reauthed.Done<RecoveryRecord>>(s.setPosture(RecoveryChoiceKind.OPERATOR, assertNotNull(s.operatorOffer()), understood = true, password = password)).value
    }

    private fun World.ops(op: Host): WireOperatorRoutes = op.operator(op.session(origin)!!)

    /**
     * A database with live sessions (four devices of two accounts and the operator's), links in progress (open and
     * answered), device links in progress (open and approved, not picked up) and requests for the operator's help (before
     * the mailed code, past it, answered by the operator, and a decoy of no account). The command, run while the server
     * runs on the database, is refused and changes nothing. Run on the put-back files with the server stopped, it ends
     * every session, marks every device signed out, closes every link and device link, closes every request of an account
     * for the operator's help (past the mailed code: ended as refused, its answer dropped; before it: cancelled) and leaves
     * the decoy as it was, writes its record into the server's own settings, and leaves
     * every row of the accounts' content and settings, the audit, the retention fence and the change counter as they
     * were; every table but `device_links` (whose rows in progress go, as a cancel removes them) and `meta` (one row more:
     * the record) holds as many rows as before. A second run ends and closes nothing.
     */
    @Test fun theCommandEndsAndClosesWhatIsInProgressRemovesNoDataAndASecondRunEndsNothing() = world {
        val op = operator()
        val ah = member("alice")
        val bh = member("bob")
        val second = passwordDevice("alice2", email)
        for (h in listOf(op, ah, bh, second)) account(h).synced()
        val aliceId = ah.session(origin)!!.userId

        val running = adminRestored(server.envFile)
        assertEquals(1, running.code, "refused while the server runs: ${running.out} ${running.err}")
        assertTrue("stop the server" in running.err && "Nothing was changed." in running.err, running.err)
        for (h in listOf(op, ah, bh, second)) account(h).synced()
        assertNull(ah.endedByServer(origin), "nothing was ended")

        val snapshot = takeSnapshot()
        restoreFrom(snapshot) { env ->
            val now = server.now()
            db(env) { c ->
                c.exec("INSERT INTO links(linkId,kind,creatorUserId,createdAt,expiresAt,offer,state) VALUES(?,'connect',?,?,?,'{}','open')", UUID.randomUUID().toString(), aliceId, now, now + Clock.DAY_MS)
                c.exec("INSERT INTO links(linkId,kind,creatorUserId,createdAt,expiresAt,offer,state,answer,answeredAt) VALUES(?,'connect',?,?,?,'{}','answered','{}',?)", UUID.randomUUID().toString(), aliceId, now, now + Clock.DAY_MS, now)
                c.exec("INSERT INTO device_links(linkId,userId,deviceId,state,expiresAt,createdAt) VALUES(?,?,?,'open',?,?)", UUID.randomUUID().toString(), aliceId, UUID.randomUUID().toString(), now + 60_000, now)
                c.exec("INSERT INTO device_links(linkId,userId,deviceId,state,expiresAt,createdAt,claimedAt,revealedAt,approvedAt) VALUES(?,?,?,'approved',?,?,?,?,?)", UUID.randomUUID().toString(), aliceId, UUID.randomUUID().toString(), now + 60_000, now, now, now, now)
                for ((state, user) in listOf("unverified" to aliceId, "verified" to aliceId, "fulfilled" to aliceId, "unverified" to null)) {
                    c.exec(
                        "INSERT INTO recovery_requests(requestId,userId,emailHash,rPub,pollHash,platform,state,createdAt,verifiedAt,holdEndsAt,sealed,commitHash) VALUES(?,?,?,?,?,'linux',?,?,?,?,?,?)",
                        UUID.randomUUID().toString(), user, "e-$state-$user", "r", "p-$state-$user", state, now,
                        if (state == "unverified") null else now, if (state == "unverified") null else now + Clock.DAY_MS,
                        if (state == "fulfilled") "sealed" else null, if (state == "fulfilled") "commit" else null,
                    )
                }
            }
            val counts = db(env) { it.rowCounts() }
            val before = db(env) { c -> untouched.associateWith { c.rows(it) } }
            val requestsBefore = db(env) { it.requestRowsKept() }
            val liveSessions = db(env) { it.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL") }
            val liveDevices = db(env) { it.long("SELECT COUNT(*) FROM devices WHERE signedOutAt IS NULL AND revokedAt IS NULL") }
            assertTrue(liveSessions >= 4 && liveDevices >= 4, "live sessions $liveSessions, devices $liveDevices")
            // The two connect links put in above, and the enrol links in progress the members were registered through.
            val openLinks = db(env) { it.long("SELECT COUNT(*) FROM links WHERE state IN ('open','answered')") }
            assertTrue(openLinks >= 2, "links in progress $openLinks")
            assertNull(record(env), "no record before the command")

            val at0 = server.now()
            val ran = adminRestored(env)
            val at1 = server.now()
            assertEquals(0, ran.code, "${ran.out} ${ran.err}")
            assertTrue("sessions ended: $liveSessions " in ran.out && "devices marked signed out: $liveDevices\n" in ran.out, ran.out)
            assertTrue("\n  links in progress closed: $openLinks\n" in ran.out && "\n  device links in progress closed: 2\n" in ran.out, ran.out)
            assertTrue("\n  requests for the operator's help closed: 3\n" in ran.out, ran.out)
            assertFalse("counter" in ran.out, "the command says nothing of a change counter: ${ran.out}")

            db(env) { c ->
                assertEquals(0L, c.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL"), "every session ended")
                assertEquals(0L, c.long("SELECT COUNT(*) FROM devices WHERE signedOutAt IS NULL"), "every device signed out")
                assertEquals(0L, c.long("SELECT COUNT(*) FROM links WHERE state IN ('open','answered')"), "every link closed")
                assertEquals(0L, c.long("SELECT COUNT(*) FROM device_links"), "every device link in progress closed")
                assertEquals(2L, c.long("SELECT COUNT(*) FROM recovery_requests WHERE userId IS NOT NULL AND state='vetoed' AND codeMac IS NULL AND sealed IS NULL AND commitHash IS NULL"), "past the mailed code: ended as refused, the answer dropped")
                assertEquals(1L, c.long("SELECT COUNT(*) FROM recovery_requests WHERE userId IS NOT NULL AND state='unverified' AND cancelledAt IS NOT NULL"), "before it: cancelled")
                assertEquals(0L, c.long("SELECT COUNT(*) FROM recovery_requests WHERE userId IS NOT NULL AND state IN ('verified','fulfilled')"), "none left waiting or answered")
                assertEquals(requestsBefore, c.requestRowsKept(), "no other column of a request changed, and the decoy is as it was")
                val after = c.rowCounts()
                assertEquals(counts - "device_links" - "meta", after - "device_links" - "meta", "no row of any other table removed or added, changes included")
                assertEquals(counts.getValue("meta") + 1, after.getValue("meta"), "one row of meta: the command's record")
                assertEquals(before, untouched.associateWith { c.rows(it) }, "the accounts' content and settings, the requests, the audit, the fence and the counter are as they were")
            }

            // The record: the time and the counts, in the server's own settings, and printed.
            val rec = assertNotNull(record(env), "the command's record")
            val at = Instant.parse(rec.substringBefore(' ')).toEpochMilli()
            assertTrue(at in at0..at1, "the record's time is the run's: $rec")
            assertEquals(
                "sessions=$liveSessions devices=$liveDevices links=$openLinks deviceLinks=2 requests=3",
                rec.substringAfter(' '), "the record's counts",
            )
            assertTrue("$rec\n" in ran.out, "the command prints its record: ${ran.out}")

            val again = adminRestored(env)
            assertEquals(0, again.code, again.err)
            for (line in listOf("sessions ended: 0 ", "devices marked signed out: 0\n", "\n  links in progress closed: 0\n", "\n  device links in progress closed: 0\n", "\n  requests for the operator's help closed: 0\n")) {
                assertTrue(line in again.out, "a second run ends nothing: ${again.out}")
            }
            db(env) { c -> assertEquals(before, untouched.associateWith { c.rows(it) }, "and changes nothing else") }
        }
        // The server starts on the database the command left; a new sign-in works.
        assertIs<SignIn.SignedIn>(pinnedDevice("after").onboarding(origin).signIn(email, password))
    }

    /**
     * Over the real server, after a restore and the command: every device's next request ends its session, as one the
     * server ended, and the device keeps what it holds; a device revoked after the backup can neither sync nor renew, with
     * the access token or the refresh token it still holds, and its account's devices list shows it signed out; the device
     * on which the password was changed after the backup signs in again with the former password; the
     * password in force before the backup signs in and the one set after it is refused; no answer to any device names the
     * restore. (Without the command, the device revoked after the backup synced again with the access token it held.)
     */
    @Test fun afterTheCommandEverySessionEndsAndADeviceRevokedAfterTheBackupCannotSyncOrRenewWithWhatItHolds() = world {
        val op = operator()
        val ah = member("alice")
        val kept = passwordDevice("kept", email)
        val lost = passwordDevice("lost", email)
        val a = account(ah)
        val v = assertNotNull(a.personalVaultId)
        assertNull(a.putItem(v, doc("before")).second)
        for (h in listOf(op, ah, kept, lost)) account(h).synced()
        val lostId = lost.session(origin)!!.session.deviceId
        val keptId = kept.session(origin)!!.session.deviceId
        val lostAccess = lost.session(origin)!!.accessToken
        val lostRefresh = lost.session(origin)!!.refreshToken
        val snapshot = takeSnapshot()
        assertIs<Reauthed.Done<*>>(ah.settings(ah.session(origin)!!).revoke(lostId, password), "Alice revokes the lost device after the backup")
        assertIs<Reauthed.Done<Unit>>(ah.changePassword(ah.session(origin)!!, password, newPassword), "and changes her password")
        val held = listOf(ah, kept, lost).associateWith { itemNames(account(it).items(v)) }
        val sessions = listOf(op, ah, kept, lost).associateWith { account(it) }

        val mark = proxy.mark()
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}") } }

        for ((h, s) in sessions) {
            s.sync()
            assertEquals(WireErrors.SESSION_REVOKED, h.endedByServer(origin)?.code, "${tag(h)}: its session ended")
            assertNull(h.session(origin), "${tag(h)}: signed out")
            held[h]?.let { assertEquals(it, itemNames(s.items(v)), "${tag(h)}: what it held is kept") }
        }
        // The lost device, with what it still holds: no sync, no renewal.
        val sync = lost.withToken(origin, lostAccess).call(WireRoute.SYNC, decode = { it })
        assertEquals(401, assertIs<WireResult.Refused>(sync, "the access token it holds is refused").status)
        val renew = lost.client(origin).call(WireRoute.REFRESH, bodyJson = WireJson.json.encodeToString(RefreshRequest.serializer(), RefreshRequest(lostRefresh)), decode = { it })
        assertEquals(WireErrors.SESSION_REVOKED, assertIs<WireResult.Refused>(renew, "the refresh token it holds is refused").error.error)

        // The device on which the password was changed after the backup signs in again with the FORMER password, syncs,
        // and holds what it held.
        assertIs<SignIn.SignedIn>(signInAgain(ah), "the device that changed the password after the backup signs in with the former one")
        assertIs<SyncOutcome.Synced>(account(ah).sync())
        assertEquals(setOf("before"), itemNames(account(ah).items(v)))

        // The former password signs in; the one set after the backup does not.
        val fresh = pinnedDevice("fresh")
        assertIs<SignIn.SignedIn>(fresh.onboarding(origin).signIn(email, password), "the former password signs in")
        val refused = pinnedDevice("refused")
        assertEquals(SignIn.InvalidCredentials, refused.onboarding(origin).signIn(email, newPassword), "the password set after the backup is refused")
        val list = assertIs<Fetched.Ok<List<io.silencelen.andvari.core.model.wire.Device>>>(fresh.settings(fresh.session(origin)!!).list()).value
        assertEquals(false, list.single { it.deviceId == lostId }.live, "the account's devices list shows the lost device signed out")
        assertEquals(false, list.single { it.deviceId == keptId }.live, "and every other device not signed in again")
        assertEquals(setOf("before"), itemNames(account(fresh).also { it.synced() }.items(v)))

        val named = proxy.since(mark).filter { x -> listOfNotNull(x.upstream, x.served).any { "restor" in it.text.lowercase() } }
        assertTrue(named.isEmpty(), "no answer to any device names the restore: ${named.map { it.req.route }}")
    }

    /**
     * The check's sequence: the replaced database's write-ahead file (`andvari.db-wal`, with its `-shm`) left beside the
     * put-back snapshot, as an unclean stop followed by "put andvari.db back" leaves it. The command refuses before it opens
     * anything, names the files, gives the one way out, and the put-back file is byte for byte as it was; so too for a run
     * that would be refused for another reason (a database of another baseline). Once the way out is followed (the two
     * files moved to another folder, the backup's file copied into place again), the command runs, and the database is
     * the snapshot's.
     */
    @Test fun aWriteAheadFileOfTheReplacedDatabaseBesideThePutBackFileIsRefusedAndTheFileIsLeftByteForByte() = world {
        operator()
        val ah = member("alice")
        val a = account(ah)
        val v = assertNotNull(a.personalVaultId)
        for (i in 1..3) assertNull(a.putItem(v, doc("before $i")).second)
        a.synced()
        val snapshot = takeSnapshot()
        val snapItems = open(snapshot.db.path) { it.long("SELECT COUNT(*) FROM items") }
        for (i in 1..40) assertNull(a.putItem(v, doc("after $i")).second)
        a.synced()
        val live = File(HostCli.configFrom(server.envFile).dbPath)
        val wal = File(live.path + "-wal")
        val shm = File(live.path + "-shm")
        assertTrue(wal.length() > 0 && shm.exists(), "the running server's write-ahead file")
        fun stale(dir: File) {
            Files.copy(wal.toPath(), File(dir, "andvari.db-wal").toPath())
            Files.copy(shm.toPath(), File(dir, "andvari.db-shm").toPath())
        }

        val (dbA, envA) = putBack(snapshot, "staleA", ::stale)
        val shaA = sha(dbA)
        val rA = adminRestored(envA)
        assertEquals(1, rA.code, "${rA.out} ${rA.err}")
        assertTheOneWayOut(rA.err, "andvari.db-wal", "andvari.db-shm")
        assertTrue("If the server is running, stop the server (and anything else that has the database open) first." in rA.err, rA.err)
        assertEquals(shaA, sha(dbA), "the put-back file is byte for byte as it was")
        assertTrue(File(dbA.path + "-wal").exists(), "and the write-ahead file is still beside it")

        // A run that would be refused for another reason.
        val (dbB, envB) = putBack(snapshot, "staleB") { dir ->
            open(File(dir, "andvari.db").path) { c -> c.exec("UPDATE meta SET value='another-baseline' WHERE key='baseline'") }
            stale(dir)
        }
        val shaB = sha(dbB)
        val rB = adminRestored(envB)
        assertEquals(1, rB.code, rB.err)
        assertTheOneWayOut(rB.err, "andvari.db-wal", "andvari.db-shm")
        assertEquals(shaB, sha(dbB), "a run refused for another reason leaves the file byte for byte as it was too")

        // The one way out the message gives: move the two files out (kept), copy the backup's file into place again, then
        // run the command again.
        oneWayOut(dbA, snapshot.db, "andvari.db-wal", "andvari.db-shm")
        val ok = adminRestored(envA)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
        assertEquals("ok", open(dbA.path) { it.text("PRAGMA integrity_check") })
        assertEquals(snapItems, open(dbA.path) { it.long("SELECT COUNT(*) FROM items") }, "the database is the snapshot's")
        assertEquals(listOf("andvari.db", "andvari.env", "blobs"), dbA.parentFile.list()!!.sorted(), "the finished run leaves no file beside the database")
    }

    /**
     * A rollback journal beside the database. A program writing the database (here: one that ends every session) is killed
     * part-way and leaves its hot journal. The command refuses before opening anything and the file is byte for byte as it
     * was; the same journal laid beside another put-back copy (a journal of a database the backup replaced) is refused
     * the same way, that copy untouched. As the message's sentence for an operator who no longer has the backup's file
     * says, opening the database once (`andvari admin status`) puts it back as it was; the command then runs, and the
     * database holds nothing of the stopped program's writes.
     */
    @Test fun aRollbackJournalBesideTheDatabaseIsRefusedAndAProgramStoppedPartWayIsPutBackByTheStatusCommand() = world {
        operator()
        val ah = member("alice")
        account(ah).synced()
        val snapshot = takeSnapshot()
        val (db, env) = putBack(snapshot, "killed")
        val liveBefore = open(db.path) { it.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL") }
        assertTrue(liveBefore >= 2)

        val child = javaChild("io.silencelen.andvari.hostile.HotJournalChild", db.path).start()
        assertEquals("ready", child.inputStream.bufferedReader().readLine(), "the child began writing")
        child.destroyForcibly()
        assertTrue(child.waitFor(60, TimeUnit.SECONDS))
        val journal = File(db.path + "-journal")
        assertTrue(journal.length() > 0, "the stopped program left its journal")

        val sha = sha(db)
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue("Left over beside the database: andvari.db-journal." in r.err, r.err)
        assertTrue("run `andvari admin status` once" in r.err && r.err.trim().endsWith("Nothing was changed."), r.err)
        assertEquals(sha, sha(db), "byte for byte as it was")
        assertTrue(journal.exists(), "the journal is left where it is")

        // The same journal beside another put-back copy: refused, that copy untouched.
        val (other, otherEnv) = putBack(snapshot, "foreign") { dir -> Files.copy(journal.toPath(), File(dir, "andvari.db-journal").toPath()) }
        val shaOther = sha(other)
        val ro = adminRestored(otherEnv)
        assertEquals(1, ro.code, ro.err)
        assertTrue("Left over beside the database: andvari.db-journal." in ro.err, ro.err)
        assertEquals(shaOther, sha(other), "a copy with a journal of another database beside it is byte for byte as it was")

        // The status command opens the database once, which puts it back; the command then runs.
        assertEquals(0, adminCommand(env, "status").code)
        assertFalse(journal.exists() || File(db.path + "-wal").exists(), "nothing is left beside the database")
        assertEquals(0L, open(db.path) { it.long("SELECT COUNT(*) FROM meta WHERE key LIKE 'unfinished %'") }, "nothing of the stopped program's writes")
        assertEquals(liveBefore, open(db.path) { it.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL") }, "the sessions are as they were")
        val ok = adminRestored(env)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
        assertTrue("sessions ended: $liveBefore " in ok.out, ok.out)
        assertEquals("ok", open(db.path) { it.text("PRAGMA integrity_check") })
    }

    /** A file that is not a database is refused as what it is, never as a database open elsewhere, and is left as it was. */
    @Test fun aFileThatIsNotADatabaseIsRefusedAsWhatItIs() = world {
        operator()
        val snapshot = takeSnapshot()
        val (db, env) = putBack(snapshot, "notadb")
        db.writeText("this is not a database at all, but a text file of some length ".repeat(100))
        val sha = sha(db)
        val r = adminRestored(env)
        assertEquals(1, r.code, r.err)
        assertTrue("is not an SQLite database" in r.err, r.err)
        assertFalse("open in another process" in r.err || "stop the server" in r.err, r.err)
        assertTrue("nothing was changed" in r.err, r.err)
        assertEquals(sha, sha(db))
    }

    /**
     * The refusal for leftover files [names] beside the database, whatever left them there: it names them and gives ONE
     * way out (move them out of the folder and keep them, COPY the backup's file into place again, run the command again).
     * No sentence of it says to move a file out without saying to copy the backup's file into place again, and no other
     * command of the tool is named before that way out.
     */
    private fun assertTheOneWayOut(err: String, vararg names: String) {
        val files = names.joinToString(" and ")
        assertTrue("Left over beside the database: $files." in err, err)
        assertTrue("move $files out of this folder and keep" in err, err)
        val copy = err.indexOf("copy the backup's andvari.db into place again (copy it, never move it")
        assertTrue(copy >= 0, err)
        assertTrue("then run `andvari admin restored` again" in err, err)
        for (s in err.split(Regex("(?<=\\.) "))) {
            if (" out of " in s) assertTrue("copy the backup's andvari.db into place again" in s, "a move out without the copy: $s")
        }
        val other = Regex("`andvari admin (?!restored`)").find(err)
        assertTrue(other == null || other.range.first > copy, "another command of the tool before the way out: $err")
        assertTrue(err.trim().endsWith("Nothing was changed."), err)
    }

    /** The one way out, as an operator follows it: [names] moved to another folder and kept, [backup] copied into place as [db] again. */
    private fun World.oneWayOut(db: File, backup: File, vararg names: String) {
        val aside = Files.createTempDirectory(server.dir.toPath(), "aside").toFile()
        for (n in names) Files.move(File(db.parentFile, n).toPath(), File(aside, n).toPath())
        Files.copy(backup.toPath(), db.toPath(), StandardCopyOption.REPLACE_EXISTING)
        assertTrue(backup.isFile && names.all { File(aside, it).isFile }, "the backup's file and the leftover files are kept")
    }

    /**
     * A `-shm` alone beside the put-back snapshot (the running server's, copied): the command refuses before it opens
     * anything, gives the one way out, and the put-back file and the `-shm` are as they were. Following the way out ends
     * with exit 0, a database whose integrity check is ok, and nothing beside it.
     */
    @Test fun aShmAloneBesideTheDatabaseIsRefusedAndTheOneWayOutEndsWithTheBackupsDatabase() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val shm = File(HostCli.configFrom(server.envFile).dbPath + "-shm")
        assertTrue(shm.exists(), "the running server's -shm")
        val (db, env) = putBack(snapshot, "shmAlone") { dir -> Files.copy(shm.toPath(), File(dir, "andvari.db-shm").toPath()) }
        val sha = sha(db)
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTheOneWayOut(r.err, "andvari.db-shm")
        assertEquals(sha, sha(db), "byte for byte as it was")
        assertTrue(File(db.path + "-shm").exists(), "the -shm is left where it is")

        oneWayOut(db, snapshot.db, "andvari.db-shm")
        val ok = adminRestored(env)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
        assertEquals("ok", open(db.path) { it.text("PRAGMA integrity_check") })
        assertEquals(listOf("andvari.db", "andvari.env", "blobs"), db.parentFile.list()!!.sorted(), "nothing is left beside the database")
    }

    /**
     * The second look's sequence. The backup's file is a snapshot with 250,000 more live sessions, so that a run takes long
     * enough to be stopped inside it. A run of the command on a put-back copy, in a process of its own, is killed after it
     * has written into the database file itself, and leaves its rollback journal. The next run refuses before it opens
     * anything: the file byte for byte as it was, the journal where it was, and the one way out in its message (an
     * operator whose run was just stopped has also just put a backup back: no way out by cause). Following it (the journal
     * moved to another folder and kept, the backup's file copied into place again, the command run again) ends with exit
     * 0, a database whose integrity check is ok, and every session of the backup ended.
     */
    @Test fun aRunOfTheCommandKilledPartWayIsRefusedNextTimeAndTheOneWayOutEndsWithTheBackupsDatabase() = world {
        operator()
        account(member("alice")).synced()
        val small = takeSnapshot()
        val (backupDb, _) = putBack(small, "backup")
        open(backupDb.path) { c ->
            val (dev, user) = c.createStatement().use { st ->
                st.executeQuery("SELECT deviceId,userId FROM devices LIMIT 1").use { rs -> assertTrue(rs.next()); rs.getString(1) to rs.getString(2) }
            }
            c.autoCommit = false
            c.prepareStatement(
                "INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,clientPlatform,createdAt) " +
                    "VALUES(?,?,?,?,?,?,?,'linux',?)",
            ).use { st ->
                for (i in 0 until 250_000) {
                    st.setString(1, UUID.randomUUID().toString()); st.setString(2, dev); st.setString(3, user)
                    st.setString(4, UUID.randomUUID().toString()); st.setLong(5, Long.MAX_VALUE / 2)
                    st.setString(6, UUID.randomUUID().toString()); st.setLong(7, Long.MAX_VALUE / 2); st.setLong(8, 1L)
                    st.addBatch()
                    if (i % 10_000 == 0) st.executeBatch()
                }
                st.executeBatch()
            }
            c.commit()
        }
        val backup = Snapshot(backupDb, small.blobs)
        val total = open(backupDb.path) { it.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL") }
        assertTrue(total > 250_000)
        val backupSha = sha(backupDb)

        val (db, env) = putBack(backup, "killed")
        val journal = File(db.path + "-journal")
        val modified = db.lastModified()
        val child = javaChild("io.silencelen.andvari.server.MainKt", "admin", "restored", "--env-file", env.path).start()
        val t0 = System.nanoTime()
        while (!(journal.length() > 0 && db.lastModified() != modified) && child.isAlive && System.nanoTime() - t0 < 120_000_000_000L) Thread.sleep(2)
        val alive = child.isAlive
        child.destroyForcibly()
        assertTrue(child.waitFor(60, TimeUnit.SECONDS))
        assertTrue(alive, "the run was killed inside its transaction")
        assertTrue(journal.length() > 0, "the killed run left its journal")
        assertTrue(sha(db) != backupSha, "the killed run had written into the database file itself")

        val sha = sha(db)
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTheOneWayOut(r.err, "andvari.db-journal")
        assertEquals(sha, sha(db), "byte for byte as it was")
        assertTrue(journal.exists(), "the journal is left where it is")

        oneWayOut(db, backupDb, "andvari.db-journal")
        val ok = adminRestored(env)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
        assertTrue("sessions ended: $total " in ok.out, ok.out)
        assertEquals("ok", open(db.path) { it.text("PRAGMA integrity_check") })
        assertEquals(listOf("andvari.db", "andvari.env", "blobs"), db.parentFile.list()!!.sorted(), "nothing is left beside the database")
    }

    /**
     * A run on a database that cannot be read (one page of it, the sessions table's, overwritten with zeros): the command
     * says that the database could not be read and to copy the backup's file into place again. Its integrity check
     * refuses it before the first change, so it says that nothing was changed (decided on 22 November 2026; before, the
     * run failed inside its transaction and did not say so). Following that ends with exit 0 and a database whose
     * integrity check is ok.
     */
    @Test fun aRunOnADatabaseThatCannotBeReadSaysSoAndToCopyTheBackupsFileIntoPlaceAgain() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (db, env) = putBack(snapshot, "unreadable")
        val (pageSize, root) = open(db.path) { it.long("PRAGMA page_size") to it.long("SELECT rootpage FROM sqlite_master WHERE name='sessions'") }
        assertTrue(root > 1)
        RandomAccessFile(db, "rw").use { f -> f.seek((root - 1) * pageSize); f.write(ByteArray(pageSize.toInt())) }
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue("the database ${db.path} could not be read" in r.err, r.err)
        assertTrue("copy the backup's andvari.db into place again, then run `andvari admin restored` again" in r.err, r.err)
        assertTrue("nothing was changed" in r.err, r.err)

        Files.copy(snapshot.db.toPath(), db.toPath(), StandardCopyOption.REPLACE_EXISTING)
        val ok = adminRestored(env)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
        assertEquals("ok", open(db.path) { it.text("PRAGMA integrity_check") })
    }

    /** A run of the command over the snapshot as the server's next start; what it printed. */
    private fun World.restoreWithTheCommand(snapshot: Snapshot): String {
        var out = ""
        restoreFrom(snapshot) { env -> adminRestored(env).also { assertEquals(0, it.code, "${it.out} ${it.err}"); out = it.out } }
        return out
    }

    /**
     * A request the operator had already answered before the backup ("ready"): its requester's device has opened the
     * answer, confirmed the account and holds the step that sets a new master password. After the restore and the
     * command it cannot finish it: the commit is refused, and Alice's master password is as it was. (A restore brings a
     * request back as the snapshot held it, so without the command one answered before the snapshot is "ready" again even
     * when the account refused it after the snapshot, and can be finished with no further act of anyone.)
     */
    @Test fun aRequestTheOperatorHadAnsweredBeforeTheBackupCannotBeFinishedAfterTheCommand() = world(extraSetup = recoveryArgs()) {
        val oh = operator()
        val ah = member("alice")
        optIn(ah)
        val uvk = ah.session(origin)!!.session.account.uvk.copyOut()
        val instanceId = oh.trust.pinFor(origin)!!.instanceId
        val (d, waiting) = asking("requester")
        server.advance(7 * Clock.DAY_MS + Clock.MINUTE_MS)
        val row = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops(oh).recoveryRequests()).value.single()
        assertIs<Reauthed.Done<Unit>>(ops(oh).fulfil(row.requestId, answerFor(row, instanceId, uvk), password), "the operator answers it")
        val check = assertIs<AssistedStep.CheckAccount>(d.assisted.poll(waiting), "ready: on to the account check")
        val choose = assertIs<AssistedStep.ChoosePassword>(d.assisted.confirmAccount(check, same = true))
        val snapshot = takeSnapshot()

        val out = restoreWithTheCommand(snapshot)

        val r = d.assisted.commit(choose, "a new Passphrase for alice 4".toCharArray())
        assertTrue(r !is AssistedStep.Recovered, "the requester cannot finish the request: $r")
        assertIs<SignIn.SignedIn>(pinnedDevice("fresh").onboarding(origin).signIn(email, password), "Alice's master password is as it was")
        assertTrue("\n  requests for the operator's help closed: 1\n" in out, out)
    }

    /**
     * A request waiting in its hold at the backup. After the restore and the command it is no longer listed for the
     * operator and cannot be answered; the requester's device learns the end at its next ask (the poll's stop
     * `vetoed`, which the shared engine shows as `OperatorHelpStage.VETOED`), and the same device can ask again.
     */
    @Test fun aRequestWaitingAtTheBackupIsNoLongerListedOrAnswerableAndItsDeviceLearnsTheEndAndCanAskAgain() = world(extraSetup = recoveryArgs()) {
        val oh = operator()
        val ah = member("alice")
        optIn(ah)
        val uvk = ah.session(origin)!!.session.account.uvk.copyOut()
        val instanceId = oh.trust.pinFor(origin)!!.instanceId
        val (d, waiting) = asking("requester")
        assertEquals(RecoveryRequestState.HOLDING, waiting.state)
        val row = assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops(oh).recoveryRequests()).value.single()
        assertEquals(RecoveryRequestState.HOLDING, row.state, "listed for the operator in its hold")
        val answer = answerFor(row, instanceId, uvk)
        val snapshot = takeSnapshot()

        val out = restoreWithTheCommand(snapshot)
        // Past the hold, when the operator could have answered it.
        server.advance(7 * Clock.DAY_MS + Clock.MINUTE_MS)

        account(oh).sync()
        assertIs<SignIn.SignedIn>(signInAgain(oh, who = "op@example.org"))
        assertTrue(assertIs<Fetched.Ok<List<AdminRecoveryRequest>>>(ops(oh).recoveryRequests()).value.none { it.requestId == row.requestId }, "no longer listed for the operator")
        val answered = ops(oh).fulfil(row.requestId, answer, password)
        assertTrue(answered !is Reauthed.Done<*>, "and cannot be answered: $answered")

        val ended = assertIs<AssistedStep.Stopped>(d.assisted.poll(waiting), "the requester's next ask")
        assertEquals(RecoveryRequestState.VETOED, ended.reason, "it learns the end")
        // It asks again, on the same device.
        val target = assertIs<AssistedStep.ConfirmTarget>(d.assisted.start(email, origin), "the same device can start again")
        val seen = Steps.mailCount(server, email, "recovery_request_code")
        val requested = assertIs<AssistedStep.Requested>(d.assisted.request(target))
        val again = assertIs<AssistedStep.Waiting>(d.assisted.verifyCode(requested, Steps.awaitCode(server, email, "recovery_request_code", seen)))
        assertEquals(RecoveryRequestState.HOLDING, again.state, "the new request waits in its hold")
        assertTrue("\n  requests for the operator's help closed: 1\n" in out, out)
    }

    /**
     * A request whose mailed code was not entered at the backup. After the restore and the command the right code is
     * answered as a cancelled request (`request_cancelled`, which the shared engine shows with `CopyKey.ASSIST_REQUEST_CANCELLED`).
     */
    @Test fun aRequestBeforeItsMailedCodeIsCancelledByTheCommand() = world(extraSetup = recoveryArgs()) {
        operator()
        optIn(member("alice"))
        val (d, requested, code) = requested("requester")
        val snapshot = takeSnapshot()

        val out = restoreWithTheCommand(snapshot)

        val r = assertIs<AssistedStep.Stopped>(d.assisted.verifyCode(requested, code), "the right code after the command")
        assertEquals(WireAssistedRecovery.REQUEST_CANCELLED, r.reason)
        assertTrue("\n  requests for the operator's help closed: 1\n" in out, out)
    }

    /**
     * The command's record is one entry of the server's own settings (the time and the counts). The tool's status command
     * shows it; no answer to any device, the operator's console included, holds it, across every member's and the
     * operator's sign-in again, sync, and the console's reads.
     */
    @Test fun theRecordIsInTheServersOwnSettingsShownByTheStatusCommandAndServedByNoRoute() = world {
        val op = operator()
        val ah = member("alice")
        val bh = member("bob")
        for (h in listOf(op, ah, bh)) account(h).synced()
        val aliceId = ah.session(origin)!!.userId
        val snapshot = takeSnapshot()
        val mark = proxy.mark()
        var rec = ""
        var env0: File? = null
        restoreFrom(snapshot) { env ->
            assertEquals(0, adminRestored(env).code)
            rec = assertNotNull(record(env))
            env0 = env
        }
        val status = adminCommand(assertNotNull(env0), "status")
        assertEquals(0, status.code, status.err)
        assertTrue("last restored start: $rec\n" in status.out, status.out)

        for ((h, who) in listOf(ah to email, bh to "bob@example.org", op to "op@example.org")) {
            account(h).sync()
            assertIs<SignIn.SignedIn>(signInAgain(h, who = who), "${tag(h)} signs in again")
            account(h).synced()
        }
        val o = ops(op)
        assertIs<Fetched.Ok<*>>(o.status())
        assertIs<Fetched.Ok<*>>(o.audit())
        assertIs<Fetched.Ok<*>>(o.policy())
        assertIs<Fetched.Ok<*>>(o.accounts())
        assertIs<Fetched.Ok<*>>(o.recoveryRequests())
        assertIs<Fetched.Ok<*>>(o.accountDevices(aliceId))
        val time = rec.substringBefore(' ')
        val holding = proxy.since(mark).filter { x ->
            listOfNotNull(x.upstream, x.served).any { recordKey in it.text || rec in it.text || time in it.text || rec.substringAfter(' ') in it.text }
        }
        assertTrue(holding.isEmpty(), "no answer holds the record: ${holding.map { it.req.route }}")
        assertTrue(proxy.since(mark).any { it.req.route == WireRoute.ADMIN_STATUS }, "the console's status was read")
    }

    /**
     * The command from a second operating-system process (the server's own tool, as an operator runs it) while the test
     * server runs on the file: refused, nothing ended, and the members still sync.
     */
    @Test fun theCommandFromAnotherProcessWhileTheServerRunsIsRefusedAndEndsNothing() = world {
        operator()
        val ah = member("alice")
        account(ah).synced()
        val dbPath = HostCli.configFrom(server.envFile).dbPath
        val before = open(dbPath) { it.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL") }
        val p = javaChild("io.silencelen.andvari.server.MainKt", "admin", "restored", "--env-file", server.envFile.path).start()
        val out = p.inputStream.bufferedReader().readText()
        assertEquals(1, p.waitFor(), out)
        assertTrue("stop the server" in out && "Nothing was changed." in out, out)
        assertEquals(before, open(dbPath) { it.long("SELECT COUNT(*) FROM sessions WHERE revokedAt IS NULL") }, "nothing was ended")
        assertIs<SyncOutcome.Synced>(account(ah).sync())
        assertNull(ah.endedByServer(origin))
    }

    /**
     * Accepted (decided on 2026-11-20), pinned so that a change is a conscious one: a device revoked after the backup keeps
     * the device secret the restored database knows again, so with the master password it signs in as a KNOWN device: on
     * an account that requires a link for new devices it needs none, its login is audited as a known device, and no
     * new-device mail goes out. A wrong password does nothing, and a new device on that account needs a link.
     */
    @Test fun aDeviceRevokedAfterTheBackupSignsInAsAKnownDeviceWithTheMasterPassword() = world {
        operator()
        val ah = member("alice")
        val lost = passwordDevice("lost", email)
        for (h in listOf(ah, lost)) account(h).synced()
        val livePath = HostCli.configFrom(server.envFile).dbPath
        open(livePath) { c -> c.exec("UPDATE users SET requireLink=1 WHERE email=?", email) }
        val lostId = lost.session(origin)!!.session.deviceId
        val snapshot = takeSnapshot()
        assertIs<Reauthed.Done<*>>(ah.settings(ah.session(origin)!!).revoke(lostId, password))
        restoreFrom(snapshot) { env -> assertEquals(0, adminRestored(env).code) }
        val dbPath = HostCli.configFrom(server.envFile).dbPath
        assertEquals("live/signed out/secret", open(dbPath) {
            it.text("SELECT COALESCE(revokedAt,'live')||'/'||(CASE WHEN signedOutAt IS NULL THEN 'signed in' ELSE 'signed out' END)||'/'||(CASE WHEN deviceSecretHash IS NULL THEN 'none' ELSE 'secret' END) FROM devices WHERE deviceId='$lostId'")
        })
        account(lost).sync()
        assertEquals(WireErrors.SESSION_REVOKED, lost.endedByServer(origin)?.code)
        val mails = open(dbPath) { it.long("SELECT COUNT(*) FROM mail_outbox WHERE template='new_device'") }
        assertEquals(SignIn.InvalidCredentials, signInAgain(lost, "not the password at all 123".toCharArray()), "a wrong password does nothing")
        assertIs<SignIn.SignedIn>(signInAgain(lost), "with the master password it signs in, though the account requires a link for new devices")
        assertEquals("known_device", open(dbPath) { it.text("SELECT COALESCE(meta,'-') FROM audit WHERE type='login' ORDER BY id DESC LIMIT 1") }, "as a known device")
        assertEquals(mails, open(dbPath) { it.long("SELECT COUNT(*) FROM mail_outbox WHERE template='new_device'") }, "and no new-device mail")
        assertEquals(SignIn.LinkRequired, pinnedDevice("stranger").onboarding(origin).signIn(email, password), "a new device on that account needs a link")
    }

    /**
     * A save made on a device that keeps its copy at rest while the server was down for the restore: across the forced
     * sign-in after the command it is kept, and once its person signs in again it reaches the server.
     */
    @Test fun aSaveMadeOfflineDuringTheRestoreSurvivesTheForcedSignInAndReachesTheServer() = world {
        operator()
        member("alice")
        originListener("kept copies")
        val ah = signedIn("phone")
        val a = ah.account(origin)!!
        val v = assertNotNull(a.personalVaultId)
        assertNull(a.putItem(v, doc("before")).second)
        a.synced()
        val snapshot = takeSnapshot()
        server.cut.add("phone")
        runCatching { a.putItem(v, doc("offline 1")) }
        assertEquals(setOf("before", "offline 1"), itemNames(a.items(v)), "held on the phone, not sent")
        restoreFrom(snapshot) { env -> assertEquals(0, adminRestored(env).code) }
        server.cut.remove("phone")
        ah.account(origin)!!.sync()
        assertEquals(WireErrors.SESSION_REVOKED, ah.endedByServer(origin)?.code, "the phone's session ended")
        assertIs<SignIn.SignedIn>(signInAgain(ah))
        val s = ah.account(origin)!!
        assertTrue("offline 1" in itemNames(s.items(v)), "the unsent save is kept across the sign-in: ${itemNames(s.items(v))}")
        assertIs<SyncOutcome.Synced>(s.sync())
        assertEquals(setOf("before", "offline 1"), itemNames(s.items(v)), "after the sync the phone holds both")
        val fresh = account(passwordDevice("fresh", email))
        fresh.synced()
        assertEquals(setOf("before", "offline 1"), itemNames(fresh.items(v)), "and it reached the server")
    }

    /** Every command of the server's tool that opens the database, each with the least it needs, against [env]. */
    private fun everyCommand(env: File): List<List<String>> = listOf(
        listOf("admin", "status"), listOf("admin", "accounts"), listOf("admin", "operator"), listOf("admin", "audit"),
        listOf("admin", "disable", "bob@example.org"), listOf("admin", "enable", "bob@example.org"),
        listOf("admin", "signup", "open"), listOf("admin", "signup", "cap", "5"),
        listOf("admin", "quota", "--account", "bob@example.org", "--items", "5"),
        listOf("admin", "enrol-link"), listOf("admin", "setup-link"), listOf("admin", "reset-instance-identity"),
        listOf("setup", "--status"), listOf("setup", "--reset-setup"),
    ).map { it + listOf("--env-file", env.path) }

    /** A snapshot, the running server's database file, and Alice's device. */
    private class Forty(val snapshot: Snapshot, val live: File, val alice: Host)

    /** A snapshot of the running server; then forty saves more, which the running server's write-ahead file holds. */
    private suspend fun World.snapshotThenForty(): Forty {
        operator()
        val ah = member("alice")
        val a = account(ah)
        val v = assertNotNull(a.personalVaultId)
        for (i in 1..3) assertNull(a.putItem(v, doc("before $i")).second)
        a.synced()
        val snapshot = takeSnapshot()
        for (i in 1..40) assertNull(a.putItem(v, doc("after $i")).second)
        a.synced()
        val live = File(HostCli.configFrom(server.envFile).dbPath)
        val wal = File(live.path + "-wal")
        assertTrue(wal.length() > 0 && File(live.path + "-shm").exists(), "the running server's write-ahead file")
        return Forty(snapshot, live, ah)
    }

    /** The running server's write-ahead file and its `-shm`, copied beside the put-back file in [dir]. */
    private fun staleBeside(live: File, dir: File) {
        Files.copy(File(live.path + "-wal").toPath(), File(dir, "andvari.db-wal").toPath())
        Files.copy(File(live.path + "-shm").toPath(), File(dir, "andvari.db-shm").toPath())
    }

    /**
     * The second look's sequences: the replaced database's write-ahead file (with its `-shm`) beside the put-back snapshot,
     * whose header says rollback mode. `andvari admin status` and `admin accounts` (until now: a stack trace of SQLite's
     * "malformed database schema"), and every other command of the tool, refuse before anything opens the database, in
     * plain words with exit 1: the files named and the one way out the `restored` command gives. The put-back file and the
     * write-ahead file are byte for byte as they were.
     */
    @Test fun aWriteAheadFileBesideADatabaseNotInWriteAheadModeIsRefusedByEveryCommandOfTheToolWithTheOneWayOut() = world {
        val f = snapshotThenForty()
        val (snapshot, live) = f.snapshot to f.live
        val (db, env) = putBack(snapshot, "staleTool") { staleBeside(live, it) }
        assertFalse(io.silencelen.andvari.server.Db.headerSaysWriteAhead(db), "the put-back snapshot is in rollback mode")
        val sha = sha(db)
        val walSha = sha(File(db.path + "-wal"))
        for (argv in everyCommand(env)) {
            val r = hostTool(argv)
            assertEquals(1, r.code, "$argv: ${r.out} ${r.err}")
            assertTrue(r.err.startsWith("andvari: Left over beside the database: andvari.db-wal and andvari.db-shm."), "$argv: ${r.err}")
            assertTheOneWayOut(r.err, "andvari.db-wal", "andvari.db-shm")
            assertEquals(1, r.err.trim().lines().size, "$argv: one line, no stack trace: ${r.err}")
            assertEquals(sha, sha(db), "$argv: the put-back file is byte for byte as it was")
            assertEquals(walSha, sha(File(db.path + "-wal")), "$argv: and so is the write-ahead file")
        }
        // Plain `andvari setup` on that database: refused before anything is written, as over any existing instance.
        val newEnv = File(db.parentFile, "setup.env")
        val s = hostTool(listOf("setup", "--origin", "https://example.org", "--env-file", newEnv.path, "--db", db.path))
        assertEquals(1, s.code, "${s.out} ${s.err}")
        assertEquals("andvari: ${db.path} already exists; setup never writes over an existing instance", s.err.trim())
        assertFalse(newEnv.exists(), "setup wrote no environment file")
        assertEquals(sha, sha(db), "setup: the put-back file is byte for byte as it was")
        assertEquals(walSha, sha(File(db.path + "-wal")), "setup: and so is the write-ahead file")
    }

    /**
     * The same put-back file and stale write-ahead file, and the server's own start (the server's program in a process
     * of its own, as the image runs it, on the put-back files): refused in plain words with exit 1 (until now: a stack
     * trace), with the one way out; the two files byte for byte as they were.
     */
    @Test fun theServersStartBesideAWriteAheadFileOfAnotherDatabaseIsRefusedInPlainWordsWithExitOne() = world {
        val f = snapshotThenForty()
        val (snapshot, live) = f.snapshot to f.live
        val (db, env) = putBack(snapshot, "staleStart") { staleBeside(live, it) }
        val sha = sha(db)
        val walSha = sha(File(db.path + "-wal"))
        val pb = javaChild("io.silencelen.andvari.server.MainKt")
        pb.environment().putAll(HostCli.readEnvFile(env))
        pb.environment()["ANDVARI_PORT"] = java.net.ServerSocket(0).use { it.localPort }.toString()
        val p = pb.start()
        val text = StringBuilder()
        val reader = Thread { text.append(p.inputStream.bufferedReader().readText()) }.apply { start() }
        val ended = p.waitFor(120, TimeUnit.SECONDS)
        if (!ended) p.destroyForcibly().waitFor()
        reader.join(10_000)
        assertTrue(ended, "the server did not start: $text")
        assertEquals(1, p.exitValue(), text.toString())
        val line = text.lines().singleOrNull { "refusing to start" in it } ?: ""
        assertTrue(line.startsWith("[andvari] refusing to start: Left over beside the database: andvari.db-wal and andvari.db-shm."), text.toString())
        assertTheOneWayOut(line, "andvari.db-wal", "andvari.db-shm")
        assertFalse("Exception" in text || "\tat " in text, "no stack trace: $text")
        assertEquals(sha, sha(db), "the put-back file is byte for byte as it was")
        assertEquals(walSha, sha(File(db.path + "-wal")), "and so is the write-ahead file")
    }

    /**
     * A database in write-ahead mode with its own write-ahead file, as an unclean stop of the running server leaves it
     * (the running server's three files, copied while it is idle): the tool's status command and the server's start open
     * it as before, and the saves only the write-ahead file held are there.
     */
    @Test fun aDatabaseInWriteAheadModeWithItsOwnWriteAheadFileOpensAsBefore() = world {
        val f = snapshotThenForty()
        val live = f.live
        assertTrue(io.silencelen.andvari.server.Db.headerSaysWriteAhead(live), "the running server's database is in write-ahead mode")
        val liveItems = open(live.path) { it.long("SELECT COUNT(*) FROM items") }
        val asStopped = Snapshot(live, File(HostCli.configFrom(server.envFile).blobDir))
        val (forStatus, statusEnv) = putBack(asStopped, "uncleanA") { staleBeside(live, it) }
        assertTrue(File(forStatus.path + "-wal").length() > 0)
        val st = adminCommand(statusEnv, "status")
        assertEquals(0, st.code, "${st.out} ${st.err}")
        assertEquals(liveItems, open(forStatus.path) { it.long("SELECT COUNT(*) FROM items") }, "the saves the write-ahead file held are there")

        val (forStart, _) = putBack(asStopped, "uncleanB") { staleBeside(live, it) }
        server.restart(mapOf("ANDVARI_DB" to forStart.path, "ANDVARI_BLOB_DIR" to File(forStart.parentFile, "blobs").path))
        val a = account(f.alice)
        assertIs<SyncOutcome.Synced>(a.sync())
        val v = assertNotNull(a.personalVaultId)
        assertEquals((1..3).map { "before $it" }.toSet() + (1..40).map { "after $it" }, itemNames(a.items(v)))
    }

    /**
     * A database the tool cannot open or read: a file that is not a database, and a database whose settings table cannot
     * be read (its root page overwritten with zeros). Every command of the tool says what it was in one plain line with
     * exit 1, never a stack trace.
     */
    @Test fun everyCommandOfTheToolOnADatabaseItCannotOpenOrReadSaysWhatItWasWithExitOne() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (notDb, notDbEnv) = putBack(snapshot, "notdbTool")
        notDb.writeText("this is not a database at all, but a text file of some length ".repeat(100))
        val (corrupt, corruptEnv) = putBack(snapshot, "corruptTool")
        val (pageSize, root) = open(corrupt.path) { it.long("PRAGMA page_size") to it.long("SELECT rootpage FROM sqlite_master WHERE name='meta'") }
        assertTrue(root > 1)
        RandomAccessFile(corrupt, "rw").use { f -> f.seek((root - 1) * pageSize); f.write(ByteArray(pageSize.toInt())) }
        for ((env, words) in listOf(notDbEnv to "andvari: ${notDb.path} is not an SQLite database (", corruptEnv to "andvari: the database ${corrupt.path} could not be read (")) {
            for (argv in everyCommand(env)) {
                val r = hostTool(argv)
                assertEquals(1, r.code, "$argv: ${r.out} ${r.err}")
                assertTrue(r.err.startsWith(words), "$argv: ${r.err}")
                assertEquals(1, r.err.trim().lines().size, "$argv: one line, no stack trace: ${r.err}")
            }
        }
    }

    /**
     * A put-back file whose settings table cannot be read (its root page overwritten with zeros): the command says that the
     * database could not be read and to copy the backup's file into place again (until now: "not a database of this build,
     * baseline none"). Following that ends with exit 0.
     */
    @Test fun aRunWhoseSettingsTableCannotBeReadSaysCouldNotBeReadAndToCopyTheBackupsFileIntoPlaceAgain() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (db, env) = putBack(snapshot, "metaUnreadable")
        val (pageSize, root) = open(db.path) { it.long("PRAGMA page_size") to it.long("SELECT rootpage FROM sqlite_master WHERE name='meta'") }
        assertTrue(root > 1)
        RandomAccessFile(db, "rw").use { f -> f.seek((root - 1) * pageSize); f.write(ByteArray(pageSize.toInt())) }
        val r = adminRestored(env)
        assertEquals(1, r.code, "${r.out} ${r.err}")
        assertTrue("the database ${db.path} could not be read" in r.err, r.err)
        assertTrue("copy the backup's andvari.db into place again, then run `andvari admin restored` again" in r.err, r.err)
        assertFalse("not a database of this build" in r.err || "baseline none" in r.err, r.err)

        Files.copy(snapshot.db.toPath(), db.toPath(), StandardCopyOption.REPLACE_EXISTING)
        val ok = adminRestored(env)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
    }

    /**
     * An older database of the same baseline (one table of today's baseline missing, as an earlier development build made
     * it): the command brings it up to the baseline first, as the server's start does, and prints what it did in the words
     * the server's start logs. On a database of today's baseline it prints no such line.
     */
    @Test fun theCommandPrintsWhatTheStartUpsCatchUpDidOnAnOlderDatabaseOfTheSameBaseline() = world {
        operator()
        account(member("alice")).synced()
        val snapshot = takeSnapshot()
        val (older, olderEnv) = putBack(snapshot, "older") { dir ->
            open(File(dir, "andvari.db").path) { c -> c.exec("DROP TABLE recovery_mailbox_values") }
        }
        val r = adminRestored(olderEnv)
        assertEquals(0, r.code, "${r.out} ${r.err}")
        val line = r.out.lines().singleOrNull { "brought up" in it }
        assertNotNull(line, r.out)
        assertTrue(line.startsWith("  database brought up to baseline '${io.silencelen.andvari.server.Db.BASELINE}': created table recovery_mailbox_values"), r.out)
        assertEquals(1L, open(older.path) { it.long("SELECT COUNT(*) FROM sqlite_master WHERE name='recovery_mailbox_values'") })

        val (_, currentEnv) = putBack(snapshot, "current")
        val c = adminRestored(currentEnv)
        assertEquals(0, c.code, "${c.out} ${c.err}")
        assertFalse("brought up" in c.out, c.out)
    }

    /**
     * A database path that is a symbolic link to the put-back snapshot, with the replaced database's write-ahead file and
     * `-shm` beside the file it leads to. SQLite looks for those files beside the file the link leads to, so the guard does
     * too: `andvari admin status` (until now: the write-ahead file applied to the snapshot, which was damaged for good, and
     * the two files gone), every other command of the tool and the `restored` command refuse before anything opens the
     * database, name the link and the file it leads to, and give the one way out; the snapshot, the `-wal` and the `-shm`
     * are byte for byte as they were.
     */
    @Test fun aDatabasePathThatIsALinkToThePutBackFileIsRefusedBesideTheFileItLeadsTo() = world {
        val f = snapshotThenForty()
        val (target, env) = putBack(f.snapshot, "linkTarget") { staleBeside(f.live, it) }
        val link = File(Files.createTempDirectory(server.dir.toPath(), "linkPath").toFile(), "andvari.db")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to link.path))
        val files = listOf(target, File(target.path + "-wal"), File(target.path + "-shm"))
        val shas = files.map { sha(it) }
        for (argv in listOf(listOf("admin", "status", "--env-file", env.path)) + everyCommand(env) + listOf(listOf("admin", "restored", "--env-file", env.path))) {
            val r = hostTool(argv)
            assertEquals(1, r.code, "$argv: ${r.out} ${r.err}")
            assertTrue(r.err.startsWith("andvari: ${link.path} is a link to ${target.canonicalPath}: the files named here lie beside that file. Left over beside the database: andvari.db-wal and andvari.db-shm."), "$argv: ${r.err}")
            assertTheOneWayOut(r.err, "andvari.db-wal", "andvari.db-shm")
            assertEquals(1, r.err.trim().lines().size, "$argv: one line, no stack trace: ${r.err}")
            assertEquals(shas, files.map { sha(it) }, "$argv: the snapshot, the -wal and the -shm are byte for byte as they were")
        }
    }

    /**
     * `andvari setup` in a new data folder that holds the leftover files of another database (`-wal`, `-shm`) and no
     * database: refused before anything is created, in setup's own words (which files, that setup makes a new instance
     * only in a folder without them, that they may be moved out and kept and setup run again, and that nothing was created
     * or changed; until now it had already made an empty database and spoke of a backup). The folder holds exactly what it
     * held, and once the two files are moved out setup makes the instance.
     */
    @Test fun setupInADataFolderWithLeftoverFilesAndNoDatabaseIsRefusedBeforeAnythingIsCreated() = world {
        val f = snapshotThenForty()
        val dir = Files.createTempDirectory(server.dir.toPath(), "setupLeft").toFile()
        val data = File(dir, "data").apply { mkdirs() }
        staleBeside(f.live, data)
        val env = File(dir, "andvari.env")
        val argv = listOf("setup", "--origin", "https://example.org", "--env-file", env.path, "--data-dir", data.path)
        val shas = listOf("andvari.db-wal", "andvari.db-shm").map { sha(File(data, it)) }
        val words = "andvari: andvari.db-wal and andvari.db-shm lie in the data folder ${data.canonicalPath}. Setup makes a new instance only " +
            "in a folder without them: move andvari.db-wal and andvari.db-shm out of this folder and keep them, then run setup again. " +
            "Nothing was created or changed."
        for (run in 1..2) {
            val r = hostTool(argv)
            assertEquals(1, r.code, "run $run: ${r.out} ${r.err}")
            assertEquals(words, r.err.trim(), "run $run")
            assertEquals(listOf("andvari.db-shm", "andvari.db-wal"), data.list()!!.sorted(), "run $run: nothing was created in the folder")
            assertFalse(env.exists(), "run $run: no environment file")
            assertEquals(shas, listOf("andvari.db-wal", "andvari.db-shm").map { sha(File(data, it)) }, "run $run: the two files are as they were")
        }
        val aside = Files.createTempDirectory(server.dir.toPath(), "setupAside").toFile()
        for (n in listOf("andvari.db-wal", "andvari.db-shm")) Files.move(File(data, n).toPath(), File(aside, n).toPath())
        val ok = hostTool(argv)
        assertEquals(0, ok.code, "${ok.out} ${ok.err}")
        assertTrue(File(data, "andvari.db").length() > 0 && env.isFile, "setup made the instance")
    }

    /**
     * A database "file" that cannot be read as a file (a folder in its place), with a write-ahead file beside it: every
     * command of the tool says so in one plain line with exit 1, as for such a path without a write-ahead file, never a
     * stack trace and never as a leftover beside a put-back database.
     */
    @Test fun aFolderInTheDatabaseFilesPlaceWithAWriteAheadFileBesideItIsSaidInOnePlainLine() = world {
        val f = snapshotThenForty()
        val (_, env) = putBack(f.snapshot, "folderDb")
        val dir = Files.createTempDirectory(server.dir.toPath(), "folderInPlace").toFile()
        val folder = File(dir, "andvari.db").apply { mkdirs() }
        Files.copy(File(f.live.path + "-wal").toPath(), File(dir, "andvari.db-wal").toPath())
        HostCli.editEnvFile(env, mapOf("ANDVARI_DB" to folder.path))
        for (argv in everyCommand(env)) {
            val r = hostTool(argv)
            assertEquals(1, r.code, "$argv: ${r.out} ${r.err}")
            assertTrue(r.err.startsWith("andvari: could not open the database ${folder.path} (it is a folder, not a file): check that"), "$argv: ${r.err}")
            assertEquals(1, r.err.trim().lines().size, "$argv: one line, no stack trace: ${r.err}")
        }
    }
}
