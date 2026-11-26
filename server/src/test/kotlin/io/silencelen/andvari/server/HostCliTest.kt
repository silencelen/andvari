package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.model.wire.WireJson
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** `andvari setup` and `andvari admin` (spec 03 §7.4, §17.5; design §9.5). */
class HostCliTest {
    private fun run(vararg argv: String, env: Map<String, String> = emptyMap()): Pair<Int, String> {
        val buf = ByteArrayOutputStream()
        val code = HostCli.run(argv.toList(), PrintStream(buf)) { env[it] }
        return code to buf.toString()
    }

    @Test
    fun setup_createsTheEnvFileOwnerOnly() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", env.path).first)
        val perms = java.nio.file.Files.getPosixFilePermissions(env.toPath())
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"), perms)
        // The helper creates the file with those permissions in one step and refuses to replace a file.
        val f = File(dir, "other.env")
        HostCli.writePrivateFile(f, "A=1\n")
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"), java.nio.file.Files.getPosixFilePermissions(f.toPath()))
        assertEquals("A=1\n", f.readText())
        assertTrue(runCatching { HostCli.writePrivateFile(f, "B=2\n") }.isFailure)
    }

    /** The data directory setup creates is 0700 and its database 0600, set explicitly rather than by the umask. */
    @Test
    fun setup_createsTheDataDirAndDatabaseOwnerOnly() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        val data = File(dir, "deep/data")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", env.path, "--data-dir", data.path).first)
        val mode = { f: File -> java.nio.file.attribute.PosixFilePermissions.toString(java.nio.file.Files.getPosixFilePermissions(f.toPath())) }
        assertEquals("rwx------", mode(data))
        assertEquals("rwx------", mode(data.parentFile), "a missing parent it creates is owner-only too")
        assertEquals("rw-------", mode(File(data, "andvari.db")))
    }

    /**
     * Setup never writes over an existing instance, and a test instance is made only in a new or empty data directory:
     * checked before anything is written. (A second setup over a live database used to fail on the instance row with an
     * uncaught SQL error, after writing a test clock and mail sink into the live data directory; with `--db` pointing
     * elsewhere it ran to the end with its blob directory inside the live one.)
     */
    @Test
    fun setup_neverWritesOverAnExistingInstance_andATestInstanceNeedsANewDataDirectory() {
        val dir = TestKit.tempDir()
        val live = File(dir, "live")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", File(dir, "a.env").path, "--data-dir", live.path).first)
        val instanceId = { Db(File(live, "andvari.db").path).use { db -> db.read { c -> c.queryOne("SELECT instanceId FROM instance_setup") { it.getString(1) } } } }
        val id = instanceId()
        val before = live.walkTopDown().map { it.path to (if (it.isFile) it.readBytes().toList() else null) }.toList()
        fun refused(vararg argv: String): Boolean = runCatching { run(*argv).first }.getOrNull() == 1
        // Over the live data directory, as a test instance or a real one.
        assertTrue(refused("setup", "--test", "--stop-at-setup", "--env-file", File(dir, "b.env").path, "--data-dir", live.path))
        assertTrue(refused("setup", "--origin", "https://vault.example.org", "--env-file", File(dir, "c.env").path, "--data-dir", live.path))
        // A new data directory whose database is the live one.
        val fresh = File(dir, "fresh")
        assertTrue(refused("setup", "--test", "--stop-at-setup", "--env-file", File(dir, "d.env").path, "--data-dir", fresh.path, "--db", File(live, "andvari.db").path))
        assertFalse(fresh.exists(), "nothing is written for a refused setup")
        // A data directory that holds anything at all, database or not.
        val other = File(dir, "other").also { it.mkdirs(); File(it, "keep.txt").writeText("mine") }
        assertTrue(refused("setup", "--test", "--stop-at-setup", "--env-file", File(dir, "e.env").path, "--data-dir", other.path))
        assertEquals(listOf("keep.txt"), other.list()!!.toList())
        // A test instance with an https origin is refused by the boot rules before its data directory is made.
        val https = File(dir, "https")
        assertTrue(refused("setup", "--test", "--stop-at-setup", "--origin", "https://vault.example.org", "--env-file", File(dir, "f.env").path, "--data-dir", https.path))
        assertFalse(https.exists())
        for (n in listOf("b", "c", "d", "e", "f")) assertFalse(File(dir, "$n.env").exists(), "$n.env")
        // The live instance is untouched, file for file.
        assertEquals(before, live.walkTopDown().map { it.path to (if (it.isFile) it.readBytes().toList() else null) }.toList())
        assertEquals(id, instanceId())
        // An empty directory made beforehand (mktemp -d) is fine.
        val empty = File(dir, "empty").also { it.mkdirs() }
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", File(dir, "g.env").path, "--data-dir", empty.path).first)
    }

    /**
     * An ordinary setup's text sends the setup link to the desktop app alone: no release publishes a command-line client,
     * so the text names none (decided on 22 November 2026).
     */
    @Test
    fun setup_theSetupLinksTextNamesTheDesktopAppAndNoCommandLineClient() {
        val dir = TestKit.tempDir()
        val (code, out) = run("setup", "--origin", "https://vault.example.org", "--env-file", File(dir, "andvari.env").path, "--data-dir", File(dir, "data").path)
        assertEquals(0, code, out)
        assertTrue(out.contains("Open this in the andvari desktop app on the computer that will hold this server's operator account."), out)
        assertTrue(out.contains("Not in an app you use for your everyday account: an app holds one account per server."), out)
        assertFalse(out.contains("andvari-cli"), out)
    }

    /**
     * An ordinary setup writes `ANDVARI_STRICT_ENV=1`, so a mistyped name in `andvari.env` stops the start instead of
     * leaving that setting at its default (decided on 22 November 2026). A test instance's settings file does not hold it:
     * the test harnesses start servers on that file with names of their own.
     */
    @Test
    fun setup_writesTheStrictLineForARealInstance_andNotForATestInstance() {
        val dir = TestKit.tempDir()
        val real = File(dir, "real.env")
        assertEquals(0, run("setup", "--origin", "https://vault.example.org", "--env-file", real.path, "--data-dir", File(dir, "real").path).first)
        assertTrue(real.readLines().contains("ANDVARI_STRICT_ENV=1"), real.readText())
        val test = File(dir, "test.env")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", test.path, "--data-dir", File(dir, "test").path).first)
        assertFalse(test.readText().contains("ANDVARI_STRICT_ENV"), test.readText())
    }

    /** The server says loudly at startup that test mode is on. */
    @Test
    fun startup_saysLoudlyWhenTestModeIsOn() {
        val on = startupLines(TestKit.config())
        assertTrue(on.any { "TEST MODE IS ON" in it }, on.joinToString("\n"))
        val off = startupLines(
            Config(
                dbPath = "x.db", blobDir = "blobs", canonicalOrigin = "https://vault.example.com", forceHsts = true,
                enumSecret = ByteArray(32) { 7 }, signupSecret = ByteArray(32) { 9 },
            ),
        )
        assertTrue(off.none { "TEST MODE" in it }, off.joinToString("\n"))
    }

    @Test
    fun setup_takesTheMailSecretsFromTheEnvironmentOrAFile_andTheHelpWarnsAboutArgv() {
        val dir = TestKit.tempDir()
        val secretFile = File(dir, "graph.secret").also { it.writeText("from-a-file\nignored\n") }
        val env = File(dir, "andvari.env")
        val (code, out) = run(
            "setup", "--test", "--stop-at-setup", "--env-file", env.path, "--graph-tenant", "t", "--graph-client-id", "id",
            "--graph-sender", "support@example.com", "--graph-client-secret-file", secretFile.path,
            env = mapOf("ANDVARI_SMTP_PASS" to "from-the-env", "ANDVARI_SMTP_HOST" to "smtp.example.com"),
        )
        assertEquals(0, code, out)
        val text = env.readText()
        assertTrue(text.contains("ANDVARI_GRAPH_CLIENT_SECRET=from-a-file\n"), text)
        assertTrue(text.contains("ANDVARI_SMTP_PASS=from-the-env\n") && text.contains("ANDVARI_SMTP_HOST=smtp.example.com\n"), text)
        // A flag still wins over the environment.
        val env2 = File(TestKit.tempDir(), "b.env")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", env2.path, "--smtp-pass", "flag", env = mapOf("ANDVARI_SMTP_PASS" to "env")).first)
        assertTrue(env2.readText().contains("ANDVARI_SMTP_PASS=flag\n"))
        assertEquals(1, run("setup", "--test", "--env-file", File(TestKit.tempDir(), "c.env").path, "--smtp-pass-file", File(dir, "missing").path).first)
        val help = run("setup", "--help").second
        assertTrue(help.contains("visible to every other user") && help.contains("ANDVARI_SMTP_PASS") && help.contains("--smtp-pass-file"), help)
    }

    @Test
    fun setupTest_writesEnvAndDatabase_mintsASetupLinkWithAnOpenableOffer() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        val (code, out) = run("setup", "--test", "--stop-at-setup", "--env-file", env.path, "--port", "18080")
        assertEquals(0, code, out)
        val o = WireJson.json.parseToJsonElement(out.trim()).jsonObject
        assertEquals("http://127.0.0.1:18080", o["origin"]!!.jsonPrimitive.content)
        val link = o["setupLink"]!!.jsonPrimitive.content
        assertTrue(link.startsWith("https://andvaripass.com/l#v2.") && link.endsWith(".-"))
        assertTrue(env.readText().contains("ANDVARI_TEST_MODE=1"))

        // A client derives the link id, offer key and register token from the secret in the URL.
        val sec = assertNotNull(HostLinks.secretOf(link))
        val (linkId, offerKey, token) = HostLinks.clientView(sec)
        val config = HostCli.configFrom(env)
        Db(config.dbPath).use { db ->
            val row = db.read { c -> c.queryOne("SELECT kind,state,offer,tokenHash,creatorUserId FROM links WHERE linkId=?", linkId) { listOf(it.getString(1), it.getString(2), it.getString(3), it.getString(4), it.getString(5)) } }!!
            assertEquals("setup", row[0]); assertEquals("open", row[1]); assertEquals(ServerCrypto.hashToken(token), row[3]); assertEquals(null, row[4])
            val offer = Envelope.openB64(TestKit.crypto, offerKey, row[2]!!, "andvari/v2|link-offer|$linkId".encodeToByteArray()).decodeToString()
            val instanceId = o["instanceId"]!!.jsonPrimitive.content
            assertTrue(offer.startsWith("{\"v\":2,\"purpose\":\"setup-offer\",\"linkId\":\"$linkId\",\"origin\":\"http://127.0.0.1:18080\",\"instanceId\":\"$instanceId\""), offer)
            assertTrue(offer.contains("\"recoveryFp\":\"none\""))
        }
        // Setup never overwrites an env file.
        assertEquals(1, run("setup", "--test", "--env-file", env.path).first)
        assertTrue(run("setup", "--status", "--env-file", env.path).second.contains("waiting for the operator"))
    }

    /**
     * `admin signup cap <n>` takes only a number the server's start takes, by the start's own bound: a cap above it would
     * be written into the settings file, and every start after it would stop on it.
     */
    @Test
    fun admin_signupCap_refusesANumberTheStartWouldRefuse_andChangesNothing() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", env.path).first)
        val range = Config.NUM_RANGES.getValue("ANDVARI_SIGNUP_CAP")
        val before = env.readText()
        assertEquals(2, run("admin", "signup", "cap", (range.last + 1).toString(), "--env-file", env.path).first)
        assertEquals(before, env.readText(), "the settings file is as it was")
        assertEquals(0, run("admin", "signup", "cap", range.last.toString(), "--env-file", env.path).first)
        assertTrue(env.readText().contains("ANDVARI_SIGNUP_CAP=${range.last}\n"))
    }

    @Test
    fun admin_enrolLinkRefusedBeforeCard0_resetIdentity_signupClearsThePanelValue() {
        val dir = TestKit.tempDir()
        val env = File(dir, "andvari.env")
        assertEquals(0, run("setup", "--test", "--stop-at-setup", "--env-file", env.path).first)
        assertEquals(1, run("admin", "enrol-link", "--env-file", env.path).first)

        val config = HostCli.configFrom(env)
        val s = Services(config, Clock.SYSTEM, Db(config.dbPath), CoreTrust())
        val op = TestKit.seedAccount(s, "op@example.com", role = "operator")
        val setup = s.db.read { s.instance.setupOn(it)!! }
        val c0 = op.identity.frame(4, TestKit.cardStatement(setup.instanceId, 0, TestKit.ZERO64, config.canonicalOrigin, setup.name, "private", op.userId, op.identity.edPub, "none", 1))
        s.db.tx { c -> c.exec("INSERT INTO instance_cards(seq,hash,frame,operatorId,name,recoveryFp,storedAt) VALUES(0,?,?,?,?,?,1)", sha256Hex(c0), Bytes.toB64(c0), op.userId, setup.name, "none") }
        // Panel tightened the cap; the host command clears it.
        s.db.tx { c -> s.policy.storeOn(c, s.policy.defaults().copy(signup = io.silencelen.andvari.core.model.wire.AdminSignupPolicy("closed", 3))) }
        s.close()

        val (code, out) = run("admin", "enrol-link", "--email", "Me@Example.com", "--count", "2", "--env-file", env.path)
        assertEquals(0, code, out)
        assertEquals(2, out.trim().lines().size)
        assertEquals(0, run("admin", "signup", "cap", "50", "--env-file", env.path).first)
        assertTrue(env.readText().contains("ANDVARI_SIGNUP_CAP=50"))
        Db(config.dbPath).use { db ->
            val p = PolicyStore(config, db).get()
            assertEquals(null, p.signup.cap)
            assertEquals("closed", p.signup.mode)
            assertEquals(2L, db.read { c -> c.count("SELECT COUNT(*) FROM links WHERE kind='enrol' AND boundEmailHash=?", config.addressHash("me@example.com")) })
        }
        // reset-instance-identity wants the typed instance id, then demotes and clears in one go.
        assertEquals(1, run("admin", "reset-instance-identity", "--env-file", env.path).first)
        assertEquals(0, run("admin", "reset-instance-identity", "--confirm", setup.instanceId, "--env-file", env.path).first)
        Db(config.dbPath).use { db ->
            db.read { c ->
                assertEquals(0L, c.count("SELECT COUNT(*) FROM users WHERE role='operator'"))
                assertEquals(0L, c.count("SELECT COUNT(*) FROM instance_cards"))
                assertEquals(1L, c.count("SELECT COUNT(*) FROM links WHERE kind='setup' AND state='open'"))
                assertEquals(setup.instanceId, c.queryOne("SELECT instanceId FROM instance_setup") { it.getString(1) })
            }
        }
    }
}
