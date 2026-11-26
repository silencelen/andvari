package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Await
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import io.silencelen.andvari.core.trust.AnswerToken
import io.silencelen.andvari.core.trust.AssistedRecovery
import io.silencelen.andvari.core.trust.AssistedRecoveryFields
import io.silencelen.andvari.server.queryOne
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The shared flows ask the tool's sink what this home keeps before they send what commits at the server: a device link,
 * a registration and an answer to a request for the operator's help on a home that keeps another account at that server
 * stop there, each said in the tool's own sentence. Each against the real server: nothing was committed (the passwords
 * and kits still work, no account was made, nothing was linked) and the accounts' live sessions there are unchanged.
 */
class KeptAccountStopsTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val pub = crypto.boxKeypairFromSeed(seed).publicKey

    /** The sessions of [email]'s account the server still takes: not ended, and not given up for a newer one by a refresh. */
    private fun live(s: TestServer, email: String): Long = s.services.db.read { c ->
        c.queryOne(
            "SELECT COUNT(*) FROM sessions se JOIN users u ON u.userId = se.userId " +
                "WHERE u.email=? AND se.revokedAt IS NULL AND se.refreshConsumedAt IS NULL", email,
        ) { it.getLong(1) }
    } ?: 0L

    private fun accounts(s: TestServer, email: String): Long =
        s.services.db.read { c -> c.queryOne("SELECT COUNT(*) FROM users WHERE email=?", email) { it.getLong(1) } } ?: 0L

    /**
     * Bo's other device shows a link and approves; me's home, which keeps me at that server, takes it. The shared flow
     * stops once the link names Bo's account, before the password is asked and before the pickup is sent: nothing linked.
     */
    @Test fun aDeviceLinkOfAnotherAccountOntoAHomeThatKeepsOneStopsBeforeThePickup() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                val bo = w.account("bo@example.org")
                val liveMe = live(s, "me@example.org")
                val liveBo = live(s, "bo@example.org")
                val mark = p.seen.size
                val r = link(w, p, bo, me)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_ANOTHER_ACCOUNT_KEPT]: " + fill(ANOTHER_ACCOUNT_KEPT, s.origin, "me@example.org", ACT_LINK)), r.err)
                assertFalse(r.err.contains("Master password"), "no password asked: ${r.err}")
                assertTrue(p.seen.drop(mark).none { it.endsWith("/pickup") }, "no pickup sent: ${p.seen.drop(mark)}")
                assertEquals(liveMe, live(s, "me@example.org"))
                assertEquals(liveBo, live(s, "bo@example.org"))
                // Me's home is as it was: the same account, and its session works.
                assertTrue(w.run(me, "whoami").ok().contains("account: me@example.org"))
                w.run(me, "item", "list", "personal").ok()
                w.run(bo, "item", "list", "personal").ok()
            }
        }
    }

    /**
     * A sign-in of Bo's account on me's home, which keeps me at that server: stopped before the password is asked and
     * before anything is sent, in the tool's sentence; me's session there is as it was. On the operator's home the
     * sentence says it holds the operator's account. Before, the sign-in was sent and took the home's place for me.
     */
    @Test fun aSignInOfAnotherAccountOnAHomeThatKeepsOneSendsNothing() {
        TestServer().use { s ->
            LyingProxy(s).use { p ->
                val w = CliWorld(s)
                val me = w.account("me@example.org")
                w.account("bo@example.org")
                val liveMe = live(s, "me@example.org")
                val liveBo = live(s, "bo@example.org")
                for ((home, said) in listOf(
                    me to "[$KEY_ANOTHER_ACCOUNT_KEPT]: " + fill(ANOTHER_ACCOUNT_KEPT, s.origin, "me@example.org", ACT_SIGN_IN),
                    w.op to "[$KEY_OPERATOR_ACCOUNT_HELD]: " + fill(OPERATOR_ACCOUNT_HELD, s.origin, "op@example.org", ACT_SIGN_IN),
                )) {
                    val mark = p.seen.size
                    var asked = 0
                    val r = w.run(home, "sign-in", "--email", "bo@example.org", dial = p.address,
                        env = { if (it == "ANDVARI_PASSWORD") Steps.PASSWORD.also { asked++ } else null })
                    assertEquals(1, r.code, r.out + r.err)
                    assertTrue(r.err.contains(said), r.err)
                    assertEquals(0, asked, "no password asked")
                    assertEquals(emptyList(), p.seen.drop(mark), "nothing sent")
                }
                assertEquals(liveMe, live(s, "me@example.org"))
                assertEquals(liveBo, live(s, "bo@example.org"))
                assertTrue(w.run(me, "whoami").ok().contains("account: me@example.org"))
                w.run(me, "item", "list", "personal").ok()
            }
        }
    }

    /**
     * A registration through an enrol link on a home that keeps another account at that server: stopped before the
     * account is sent, so no account is made and the link is not spent (it then makes Carol's account on a home of her
     * own). On the operator's home the sentence says it holds the operator's account.
     */
    @Test fun aRegistrationOnAHomeThatKeepsAnotherAccountMakesNoAccount() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val liveMe = live(s, "me@example.org")
            val liveOp = live(s, "op@example.org")
            for ((home, email, said) in listOf(
                Triple(me, "carol@example.org", "[$KEY_ANOTHER_ACCOUNT_KEPT]: " + fill(ANOTHER_ACCOUNT_KEPT, s.origin, "me@example.org", ACT_REGISTRATION)),
                Triple(w.op, "dan@example.org", "[$KEY_OPERATOR_ACCOUNT_HELD]: " + fill(OPERATOR_ACCOUNT_HELD, s.origin, "op@example.org", ACT_REGISTRATION)),
            )) {
                val link = Steps.enrolLink(s, email)
                val kit = File(w.tmp, "$email-kit.txt")
                val r = w.run(home, "enrol", link, "--email", email, "--kit-out", kit.path)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains(said), r.err)
                assertEquals(0L, accounts(s, email), "no account made for $email")
                assertFalse(kit.exists())
                // The link was not spent: it makes the account on a home that keeps none.
                w.run(File(w.tmp, "$email home"), "enrol", link, "--email", email, "--kit-out", kit.path, "--trust-card", w.card0).ok()
                assertEquals(1L, accounts(s, email))
            }
            assertEquals(liveMe, live(s, "me@example.org"))
            assertEquals(liveOp, live(s, "op@example.org"))
            w.run(me, "item", "list", "personal").ok()
        }
    }

    /**
     * The operator's answer to Ann's request, asked for on Ann's own home, names Bob's account (whoever holds the
     * operator's recovery key and runs the server can make one: Bob's id under Ann's address, sealed to Ann's request,
     * with the poll serving an identity its key opens). Ann's home keeps Ann for
     * that address, so the answer is refused at the pick-up, before any account is shown or a password asked, even with
     * Bob's account ID given: nothing is committed (Bob's password still signs in), the request is kept, and the live
     * sessions of both are unchanged.
     */
    @Test fun anAnswerThatNamesAnotherAccountThanTheOneKeptForTheAddressIsRefusedAtThePickUp() {
        val bob = "bob@example.org"
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            val w = CliWorld(s)
            val ann = w.account("ann@example.org")
            val bo = w.account(bob)
            for (h in listOf(ann, bo)) w.run(h, "recovery", "operator", "--i-understand").ok()
            val seen = Steps.mailCount(s, "ann@example.org", "recovery_request_code")
            val asked = w.run(ann, "recover", "assist", "--email", "ann@example.org", "--trust-card", w.card0,
                stdin = { Steps.awaitCode(s, "ann@example.org", "recovery_request_code", seen) })
            assertEquals(0, asked.code, asked.out + asked.err)
            val requestCode = Regex("request code: ([A-Za-z0-9 -]+?)\\s{3}").find(asked.out)!!.groupValues[1].trim()

            s.advance(7 * 86_400_000L + 60_000)
            val listed = w.run(w.op, "operator", "recovery-requests").ok()
            val (request, key, _) = Regex("^(\\S+)\\s+for ann@example.org\\s+request key (\\S+)\\s+user (\\S+)", RegexOption.MULTILINE).find(listed)!!.destructured
            val boUser = w.userId(bob)
            val boAccountId = Regex("account ([0-9a-f]{32})").find(w.kit(bob).readLines().first())!!.groupValues[1]
            // The honest offline tool will not make it (it holds the answer to the copy's own address), so it is made here
            // as recovery-cli makes one, by the holder of the recovery seed who also runs the server: an account key of
            // Bob's id under Ann's address, sealed to Ann's request, and the poll serving an identity that key opens.
            val uvk = crypto.randomBytes(32)
            val idSeed = crypto.randomBytes(32)
            val servedSeed = Bytes.toB64(Envelope.seal(crypto, uvk, idSeed, Ad.idkey(boUser)))
            val servedPub = Bytes.toB64(crypto.boxKeypairFromSeed(idSeed).publicKey)
            val commit = crypto.randomBytes(32)
            val frame = AssistedRecovery.sign(crypto, crypto.signKeypairFromSeed(seed), AssistedRecoveryFields(
                instanceId, boUser, request, key, uvk, s.now(), email = "ann@example.org", commit = commit.copyOf(),
            ))
            val answer = AnswerToken.format(request, key, AssistedRecovery.commitHash(crypto, commit),
                AssistedRecovery.seal(crypto, Bytes.fromB64Exact(key, 32)!!, frame))
            val sealed = File(w.tmp, "answer.txt").apply { writeText(answer + "\n") }
            w.run(w.op, "operator", "fulfil", request, "--sealed-file", sealed.path).ok()

            val liveAnn = live(s, "ann@example.org")
            val liveBo = live(s, bob)
            val newKit = File(w.tmp, "new-kit.txt")
            val newPw: (String) -> String? = { if (it == "ANDVARI_PASSWORD") "a new Password from the answer 3" else null }
            val p = LyingProxy(s)
            p.lie = mapOf(WireRoute.RECOVERY_REQUEST_POLL to { e: JsonElement ->
                val o = e.jsonObject
                if (o["sealed"] == null) o else JsonObject(o + ("encryptedIdentitySeed" to JsonPrimitive(servedSeed)) + ("identityPub" to JsonPrimitive(servedPub)))
            })
            for (i in 1..2) {
                val r = w.run(ann, "recover", "assist", "--account-id", boAccountId, "--kit-out", newKit.path, env = newPw, dial = p.address)
                assertEquals(1, r.code, r.out + r.err)
                assertTrue(r.err.contains("[$KEY_NOT_THE_KEPT_ACCOUNT]: " + fill(NOT_THE_KEPT_ACCOUNT, s.origin, "your request's address")), r.err)
                assertFalse(r.out.contains(boAccountId), "no account shown to check: ${r.out}")
                assertFalse(newKit.exists())
            }
            assertTrue(p.seen.none { it.contains("/commit") }, "no commit sent: ${p.seen}")
            p.close()
            assertEquals(liveAnn, live(s, "ann@example.org"))
            assertEquals(liveBo, live(s, bob))
            // Nothing was committed: Bob's password still signs in, and Ann's home still keeps Ann.
            w.run(File(w.tmp, "bob again"), "sign-in", "--email", bob, "--trust-card", w.card0).ok()
            assertTrue(w.run(ann, "whoami").ok().contains("account: ann@example.org"))
        }
    }

    private fun await(buf: ByteArrayOutputStream, re: Regex): String =
        Await.until("a line matching ${re.pattern} from the other process", 120_000, { "its output so far: $buf" }) {
            re.find(buf.toString())?.groupValues?.get(1)
        }

    /** `link-device show` on [shows], and `link-device` on [joins] with its requests through [p]: the joining run. */
    private fun link(w: CliWorld, p: LyingProxy, shows: File, joins: File): CliRun {
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
            val joining = pool.submit<CliRun> {
                CliRun.run(w.s, joins, "link-device", "--link-file", linkFile.path, "--trust-card", w.card0, origin = null, out = joined, dial = p.address)
            }
            val r = joining.get(5, TimeUnit.MINUTES)
            // The showing device's run ends too (its link went nowhere); what it says is not this test's matter.
            show.get(5, TimeUnit.MINUTES)
            return r
        } finally {
            pool.shutdownNow()
        }
    }
}
