package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.client.account.TwoStepAnswer
import io.silencelen.andvari.core.client.account.TwoStepSetup
import io.silencelen.andvari.core.client.account.WireTwoStep
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.Totp
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Commands the journeys drove only through the engine, now at the command line against the real server: the vault
 * membership commands (with a reader who tries to write and a removed member who tries to read), `card rotation --file`,
 * `sign-up`, and a two-step code at sign-in.
 */
class CommandCoverageTest {
    private val crypto = createCryptoProvider()

    private fun item(name: String) = CliRun.lines("""{"type":"login","name":"$name","login":{"username":"u","password":"p-$name"}}""")

    @Test fun vaultMembershipAddRoleRemoveOfferAcceptLeaveAndIncoming() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val alice = w.account("alice@example.org")
            val bob = w.account("bob@example.org")
            val (meId, aliceId) = w.connect(me, alice)
            val (_, bobId) = w.connect(me, bob)
            val v = CliWorld.vaultId(w.run(me, "vault", "create", "Family").ok())

            // add, with a role; each member accepts with `incoming --accept` (neither flag is a usage error).
            w.run(me, "vault", "add", v, aliceId, "--role", "reader").ok()
            assertEquals(2, w.run(alice, "vault", "incoming", v).code)
            w.run(alice, "vault", "incoming", v, "--accept").ok()
            w.run(me, "vault", "add", v, bobId).ok()
            w.run(bob, "vault", "incoming", v, "--accept").ok()
            w.run(me, "item", "put", v, stdin = item("Thing")).ok()
            assertTrue(w.run(me, "vault", "list").ok().lines().first { it.startsWith(v) }.contains("3 members"))

            // A reader reads and cannot write; a writer writes.
            assertTrue(w.run(alice, "item", "list", v).ok().contains("Thing"))
            val readerWrite = w.run(alice, "item", "put", v, stdin = item("ReaderWrote"))
            assertEquals(1, readerWrite.code, readerWrite.out + readerWrite.err)
            w.run(bob, "item", "put", v, stdin = item("BobWrote")).ok()
            val seen = w.run(me, "item", "list", v).ok()
            assertTrue(seen.contains("BobWrote") && !seen.contains("ReaderWrote"), seen)

            // role: the reader becomes a writer and writes.
            w.run(me, "vault", "role", v, aliceId, "writer").ok()
            w.run(alice, "item", "put", v, stdin = item("AliceWrote")).ok()

            // remove: the removed member can no longer read the vault.
            w.run(me, "vault", "remove", v, bobId).ok()
            val removed = w.run(bob, "item", "list", v)
            assertEquals(1, removed.code, removed.out + removed.err)
            assertFalse(removed.out.contains("Thing"), removed.out)

            // offer and accept: the vault moves to Alice; then leave: I am gone from its members.
            w.run(me, "vault", "offer", v, aliceId).ok()
            w.run(alice, "vault", "accept", v).ok()
            assertTrue(w.run(alice, "vault", "list").ok().lines().first { it.startsWith(v) }.contains("owner $aliceId"))
            w.run(me, "vault", "leave", v).ok()
            assertTrue(w.run(alice, "vault", "list").ok().lines().first { it.startsWith(v) }.contains("1 members"))
            assertEquals(1, w.run(me, "item", "list", v).code, "after leaving, I cannot read it")

            // incoming --decline: a vault declined is not adopted, so its items are not readable here.
            val o = CliWorld.vaultId(w.run(alice, "vault", "create", "Other").ok())
            w.run(alice, "item", "put", o, stdin = item("Secret")).ok()
            w.run(alice, "vault", "add", o, meId).ok()
            w.run(me, "vault", "incoming", o, "--decline").ok()
            val declined = w.run(me, "item", "list", o)
            assertTrue(declined.code != 0 || !declined.out.contains("Secret"), declined.out + declined.err)
        }
    }

    @Test fun cardRotationFromTheOfflineToolsStatementFile() {
        val seed1 = crypto.randomBytes(32)
        val pub1 = crypto.boxKeypairFromSeed(seed1).publicKey
        val pub2 = crypto.boxKeypairFromSeed(crypto.randomBytes(32)).publicKey
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub1))).use { s ->
            val w = CliWorld(s)
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            assertTrue(w.run(w.op, "card", "show").ok().contains("recoveryFp:  ${Escrow.fingerprint(crypto, pub1)}"))

            assertEquals(2, w.run(w.op, "card", "rotation").code, "--file is required")
            val junk = File(w.tmp, "junk.txt").apply { writeText("not a rotation statement\n") }
            assertEquals(1, w.run(w.op, "card", "rotation", "--file", junk.path).code, "a file that holds no statement is refused")

            val statement = File(w.tmp, "rotation.txt").apply {
                writeText(s.recoveryCli(listOf("rotate", "--instance", instanceId, "--to", Bytes.toB64(pub2)), Bytes.toB64(seed1) + "\n"))
            }
            // One command: the statement checked, then uploaded with the card that names the new key.
            val fp2 = Escrow.fingerprint(crypto, pub2)
            assertTrue(w.run(w.op, "card", "rotation", "--file", statement.path, "--recovery-fp", fp2).ok().contains("card 1 stored"))
            assertTrue(w.run(w.op, "card", "show").ok().contains("recoveryFp:  $fp2"))
        }
    }

    @Test fun signUpThroughTheEmailedCode() {
        TestServer(kind = "public", mode = "open", extraEnv = mapOf("ANDVARI_SIGNUP_POW_BITS" to "10")).use { s ->
            val w = CliWorld(s)
            val carol = w.home("carol@example.org")
            val email = "carol@example.org"
            fun codes() = Steps.mailCount(s, email, "signup_code")

            // A kit that cannot be captured stops it before anything is sent: no email goes out.
            val noKit = w.run(carol, "sign-up", "--email", email, "--age-confirm", "--trust-card", w.card0)
            assertEquals(2, noKit.code, noKit.err)
            assertEquals(0, codes())

            // A wrong code is refused; nothing is registered.
            val wrong = w.run(carol, "sign-up", "--email", email, "--age-confirm", "--kit-out", w.kit(email).path, "--trust-card", w.card0, env = { name ->
                when (name) {
                    "ANDVARI_PASSWORD" -> Steps.PASSWORD
                    "ANDVARI_SIGNUP_CODE" -> if (Steps.awaitCode(s, email) == "000000") "111111" else "000000"
                    else -> null
                }
            })
            assertEquals(1, wrong.code, wrong.err)
            assertTrue(wrong.err.contains("wrong or expired"), wrong.err)
            assertFalse(w.kit(email).exists())

            // The emailed code, read as a script would from the environment: registered, the kit captured.
            val seen = codes()
            val r = w.run(carol, "sign-up", "--email", email, "--age-confirm", "--kit-out", w.kit(email).path, env = { name ->
                when (name) {
                    "ANDVARI_PASSWORD" -> Steps.PASSWORD
                    "ANDVARI_SIGNUP_CODE" -> Steps.awaitCode(s, email, seen = seen)
                    else -> null
                }
            })
            assertEquals(0, r.code, r.out + r.err)
            assertTrue(r.out.contains("registered: $email"), r.out)
            assertTrue(w.kit(email).readText().startsWith("andvari recovery kit for account"))
            w.run(carol, "item", "put", "personal", stdin = item("Mine")).ok()
            assertTrue(w.run(carol, "item", "list", "personal").ok().contains("Mine"))
        }
    }

    @Test fun aTwoStepCodeAtSignIn() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val email = "dana@example.org"
            // Two-step sign-in is turned on from another device (the engine's own Settings flow).
            val config = runBlocking {
                val d = s.device("dana phone")
                Steps.registerThrough(d, s.origin, Steps.enrolLink(s, email), email, trustGate = true)
                val two = WireTwoStep(d.client(s.origin), d.reauth(d.session(s.origin)!!))
                val ready = assertIs<TwoStepSetup.Ready>(two.setup(Steps.PASSWORD.toCharArray()))
                val cfg = Totp.parseUri(ready.secret.otpauthUri)
                assertEquals(TwoStepAnswer.Ok, two.confirm(Totp.code(crypto, cfg, s.now() / 1000)))
                cfg
            }
            s.advance(31_000)
            val dana = w.home(email)
            fun signIn(env: (String) -> String?, vararg extra: String) =
                w.run(dana, "sign-in", "--email", email, "--trust-card", w.card0, *extra, env = env)

            // No code: refused, nothing kept.
            val none = signIn({ if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null })
            assertEquals(1, none.code, none.err)
            assertTrue(none.err.contains("ANDVARI_TOTP"), none.err)
            // A wrong code: refused.
            val code = Totp.code(crypto, config, s.now() / 1000)
            val wrong = signIn({ mapOf("ANDVARI_PASSWORD" to Steps.PASSWORD, "ANDVARI_TOTP" to if (code == "000000") "111111" else "000000")[it] })
            assertEquals(1, wrong.code, wrong.err)
            // Said as a code refused, never as a wrong master password: the server asked for the code after this password.
            assertTrue(wrong.err.contains(fill(WRONG_CODE_AT_SIGN_IN, s.origin)), wrong.err)
            assertFalse(wrong.err.contains("wrong email") || wrong.err.contains(": wrong master password"), wrong.err)
            assertFalse(SavedSessions(CliHome(dana).secureState()).has(s.origin, email))
            // The right code from a file: signed in (in the next step, past any backoff the failures earned).
            s.advance(31_000)
            val codeFile = File(w.tmp, "totp.txt").apply { writeText(Totp.code(crypto, config, s.now() / 1000) + "\n") }
            assertTrue(signIn({ if (it == "ANDVARI_PASSWORD") Steps.PASSWORD else null }, "--totp-file", codeFile.path).ok().contains("signed in: $email"))
            assertTrue(SavedSessions(CliHome(dana).secureState()).has(s.origin, email))
        }
    }
}
