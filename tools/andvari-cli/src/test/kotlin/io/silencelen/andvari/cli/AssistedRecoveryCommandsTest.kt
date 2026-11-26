package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.TestServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Operator-assisted recovery (design §9.3) with the tool on every side and no terminal: the person turns operator
 * recovery on (`recovery operator`), a fresh device asks for help (`recover assist`), the operator lists the request
 * (never its code), downloads the escrow, runs `recovery-cli assist` offline with the code the person read out and
 * uploads the answer (`operator escrow`, `operator fulfil`); the fresh device confirms the account ID and sets a new
 * password and kit. A second request is vetoed from the signed-in device (`recovery-requests veto`), and a third is
 * cancelled on the device that made it, sending nothing.
 */
class AssistedRecoveryCommandsTest {
    private val crypto = createCryptoProvider()
    private val seed = crypto.randomBytes(32)
    private val pub = crypto.boxKeypairFromSeed(seed).publicKey
    private val newPw = "recovered by the Operator 77"

    private fun pw(p: String): (String) -> String? = { if (it == "ANDVARI_PASSWORD") p else null }

    @Test fun assistedRecoveryFromBothSidesThenAVetoAndACancel() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            val alice = File(tmp, "alice")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            val aliceKit = File(tmp, "alice-kit.txt")
            CliRun.run(s, alice, "enrol", Steps.enrolLink(s, "alice@example.org"), "--email", "alice@example.org", "--kit-out", aliceKit.path, "--trust-card", card0).ok()
            val accountId = Regex("account ([0-9a-f]{32})").find(aliceKit.readLines().first())!!.groupValues[1]

            // The person chooses operator recovery, only with --i-understand.
            assertEquals(2, CliRun.run(s, alice, "recovery", "operator").code)
            assertTrue(CliRun.run(s, alice, "recovery", "operator", "--i-understand").ok().contains("recovery: operator"))
            assertTrue(CliRun.run(s, alice, "recovery", "show").ok().contains("posture:  operator"))

            // A fresh device asks for help; the emailed code is typed in the same run.
            val d = File(tmp, "new phone")
            var seen = Steps.mailCount(s, "alice@example.org", "recovery_request_code")
            val asked = CliRun.run(s, d, "recover", "assist", "--email", "alice@example.org", "--trust-card", card0, env = pw(newPw),
                stdin = { Steps.awaitCode(s, "alice@example.org", "recovery_request_code", seen) })
            assertEquals(0, asked.code, asked.out + asked.err)
            val requestCode = Regex("request code: ([A-Za-z0-9 -]+?)\\s{3}").find(asked.out)!!.groupValues[1].trim()
            assertTrue(asked.out.contains("holding"), asked.out)
            assertTrue(CliRun.run(s, d, "recover", "assist").ok().contains("request kept: holding"))
            assertTrue(CliRun.run(s, alice, "recovery-requests").ok().contains("holding"), "the signed-in device sees the request")

            // In its hold the request is listed as holding, under a heading that does not say otherwise.
            val inHold = CliRun.run(s, op, "operator", "recovery-requests").ok()
            assertTrue(Regex("for alice@example.org .* holding until \\S+Z ").containsMatchIn(inHold), inHold)
            assertFalse(inHold.contains("past their hold"), inHold)

            // After the hold, the operator: the request (no code shown), the escrow, recovery-cli assist offline, the answer.
            s.advance(7 * 86_400_000L + 60_000)
            val listed = CliRun.run(s, op, "operator", "recovery-requests").ok()
            assertTrue(listed.contains("waiting for the operator (the hold ended "), listed)
            assertFalse(listed.contains(requestCode), "the operator's list never shows the request code")
            // Nor the server's account ID: the anchor below is the one on Alice's own kit.
            assertFalse(listed.contains(accountId), "the operator's list never offers the server's account ID")
            val m = Regex("^(\\S+)\\s+for alice@example.org\\s+request key (\\S+)\\s+user (\\S+)", RegexOption.MULTILINE).find(listed)!!
            val (requestId, rPub, userId) = m.destructured
            val escrow = File(tmp, "escrow.json")
            CliRun.run(s, op, "operator", "escrow", "alice@example.org", "--out", escrow.path).ok()
            // The operator types the address of the person they are helping (spec 04 §4 step 0); the anchor is the person's own kit.
            val assistOut = s.recoveryCli(
                listOf("assist", "--instance", instanceId, "--request", requestId, "--request-key", rPub, "--request-code", requestCode,
                    "--email", "alice@example.org", "--user", userId, "--identity-fp", accountId, "--identity-file", escrow.path),
                Bytes.toB64(seed) + "\n" + "RECOVER ${userId.take(8)}\n",
            )
            assertTrue(assistOut.trim().lines().last().startsWith("andvari-answer:3:$requestId:$rPub:"), assistOut)
            // The tool's whole output, as `assist … > answer.txt` writes it: the shared reader takes its last line.
            val sealed = File(tmp, "answer.txt").apply { writeText(assistOut) }
            CliRun.run(s, op, "operator", "fulfil", requestId, "--sealed-file", sealed.path).ok()
            assertTrue(CliRun.run(s, op, "operator", "recovery-requests").ok().contains("answered ("), "an answered row says so")

            // The fresh device: the account ID must be confirmed; then a new password and a new kit.
            val check = CliRun.run(s, d, "recover", "assist", env = pw(newPw))
            assertEquals(2, check.code, check.err)
            assertTrue(check.out.contains("account ID $accountId"), check.out)
            // A mistyped ID: the IDs differ, nothing changes, and the request is kept.
            val typo = accountId.dropLast(1) + (if (accountId.last() == '0') '1' else '0')
            val slip = CliRun.run(s, d, "recover", "assist", "--account-id", typo, env = pw(newPw))
            assertEquals(1, slip.code, slip.out + slip.err)
            assertTrue(slip.err.contains("[$KEY_ACCOUNT_ID_DIFFERS]") && slip.err.contains("differs from the account delivered") &&
                slip.err.contains("this device keeps the request"), slip.err)
            assertTrue(CliRun.run(s, d, "recover", "assist", env = pw(newPw)).out.contains("account ID $accountId"), "the request is still there")
            val newKit = File(tmp, "new-kit.txt")
            val done = CliRun.run(s, d, "recover", "assist", "--account-id", accountId, "--kit-out", newKit.path, env = pw(newPw))
            assertEquals(0, done.code, done.out + done.err)
            assertTrue(done.out.contains("recovered: alice@example.org"), done.out)
            assertTrue(newKit.readText().startsWith("andvari recovery kit for account $accountId"))
            CliRun.run(s, d, "whoami", env = pw(newPw)).ok()
            CliRun.run(s, d, "item", "list", "personal", env = pw(newPw)).ok()

            // A stranger's request; the signed-in device vetoes it; the stranger's next run says it stopped.
            val e = File(tmp, "attacker")
            seen = Steps.mailCount(s, "alice@example.org", "recovery_request_code")
            CliRun.run(s, e, "recover", "assist", "--email", "alice@example.org", "--trust-card", card0,
                stdin = { Steps.awaitCode(s, "alice@example.org", "recovery_request_code", seen) }).ok()
            val live = CliRun.run(s, d, "recovery-requests", env = pw(newPw)).ok()
            val vetoId = live.lines().first { it.contains("holding") }.substringBefore(' ')
            assertTrue(CliRun.run(s, d, "recovery-requests", "veto", vetoId, env = pw(newPw)).ok().contains("cancelled"))
            val stopped = CliRun.run(s, e, "recover", "assist")
            assertEquals(1, stopped.code, stopped.out + stopped.err)

            // A third request, cancelled on the device that made it: nothing is sent, and nothing is kept afterwards.
            val f = File(tmp, "third")
            seen = Steps.mailCount(s, "alice@example.org", "recovery_request_code")
            CliRun.run(s, f, "recover", "assist", "--email", "alice@example.org", "--trust-card", card0,
                stdin = { Steps.awaitCode(s, "alice@example.org", "recovery_request_code", seen) }).ok()
            // Dialed at a listener of this test's own (port 0), not a fixed port another process may hold: it counts nothing.
            ConnectionCounter().use { counter ->
                assertTrue(CliRun.run(s, f, "recover", "assist", "--cancel", dial = counter.address).ok().contains("nothing was sent"))
                assertEquals(0, counter.settled(), "cancelling sends nothing")
            }
            assertEquals(2, CliRun.run(s, f, "recover", "assist").code, "no request is kept any more")
        }
    }

    /** One member enrolled with operator recovery on, and a fresh device's open, verified request for them. */
    private class Asking(val email: String, val kit: File, val accountId: String, val device: File, val requestCode: String)

    private fun asking(s: TestServer, tmp: File, card0: String, name: String): Asking {
        val email = "$name@example.org"
        val home = File(tmp, name)
        val kit = File(tmp, "$name-kit.txt")
        CliRun.run(s, home, "enrol", Steps.enrolLink(s, email), "--email", email, "--kit-out", kit.path, "--trust-card", card0).ok()
        CliRun.run(s, home, "recovery", "operator", "--i-understand").ok()
        val d = File(tmp, "$name new phone")
        val seen = Steps.mailCount(s, email, "recovery_request_code")
        val asked = CliRun.run(s, d, "recover", "assist", "--email", email, "--trust-card", card0, env = pw(newPw),
            stdin = { Steps.awaitCode(s, email, "recovery_request_code", seen) })
        assertEquals(0, asked.code, asked.out + asked.err)
        val code = Regex("request code: ([A-Za-z0-9 -]+?)\\s{3}").find(asked.out)!!.groupValues[1].trim()
        return Asking(email, kit, Regex("account ([0-9a-f]{32})").find(kit.readLines().first())!!.groupValues[1], d, code)
    }

    /**
     * An answer for another request and a copy of another member, end to end with the real server and the real offline tool. Two requests are open for
     * two accounts: each one's answer is refused at the other's row (nothing sent) and both stay answerable. And the
     * server's lie about the member: the console shows another member's user id and recovery copy under a request; the
     * operator types the address of the person they are helping, and the offline tool refuses the copy, saying whose it is.
     */
    @Test fun eachAnswerIsRefusedAtTheOtherRequestsRow_andAnotherMembersCopyIsRefusedByTheTypedAddress() {
        TestServer(extraSetup = listOf("--recovery-pubkey", Bytes.toB64(pub))).use { s ->
            val instanceId = s.setup["instanceId"]!!.toString().trim('"')
            val tmp = Files.createTempDirectory("andvari-cli").toFile()
            val op = File(tmp, "operator")
            CliRun.run(s, op, "operator", "enrol", s.setupLink, "--email", "op@example.org", "--kit-out", File(tmp, "op-kit.txt").path).ok()
            val card0 = Regex("card0Hash:\\s+([0-9a-f]{64})").find(CliRun.run(s, op, "card", "show").ok())!!.groupValues[1]
            val ann = asking(s, tmp, card0, "ann")
            val bo = asking(s, tmp, card0, "bo")
            s.advance(7 * 86_400_000L + 60_000)
            val listed = CliRun.run(s, op, "operator", "recovery-requests").ok()
            // The listing as the command-line tool prints it: no account ID, the request key and the user id assist needs.
            fun row(email: String) = Regex("^(\\S+)\\s+for ${Regex.escape(email)}\\s+request key (\\S+)\\s+user (\\S+)", RegexOption.MULTILINE).find(listed)!!.destructured
            val (annRequest, annKey, annUser) = row(ann.email)
            val (boRequest, boKey, boUser) = row(bo.email)
            fun escrow(email: String) = File(tmp, "$email.json").also { CliRun.run(s, op, "operator", "escrow", email, "--out", it.path).ok() }
            val annCopy = escrow(ann.email)
            val boCopy = escrow(bo.email)
            fun assist(request: String, key: String, code: String, typed: String, user: String, anchor: String, copy: File) = runCatching {
                s.recoveryCli(
                    listOf("assist", "--instance", instanceId, "--request", request, "--request-key", key, "--request-code", code,
                        "--email", typed, "--user", user, "--identity-fp", anchor, "--identity-file", copy.path),
                    Bytes.toB64(seed) + "\n" + "RECOVER ${user.take(8)}\n",
                )
            }

            // F2/F3: under Ann's request the server put Bo's user id and Bo's copy (anchored to Bo's own identity, as an
            // anchor copied from the console would be). The operator types Ann's address: the tool refuses, naming Bo.
            val lie = assist(annRequest, annKey, ann.requestCode, ann.email, boUser, Regex("account ([0-9a-f]{32})").find(bo.kit.readLines().first())!!.groupValues[1], boCopy)
            val why = lie.exceptionOrNull()?.message.orEmpty()
            assertTrue("email_mismatch" in why && "This recovery copy is ${bo.email}'s, not ${ann.email}'s" in why, why)

            // The two right answers, one per request.
            val annOut = File(tmp, "ann-answer.txt").apply { writeText(assist(annRequest, annKey, ann.requestCode, ann.email, annUser, ann.accountId, annCopy).getOrThrow()) }
            val boOut = File(tmp, "bo-answer.txt").apply { writeText(assist(boRequest, boKey, bo.requestCode, bo.email, boUser, bo.accountId, boCopy).getOrThrow()) }
            // F1: each answer given to the other's row is refused before the password, and nothing is sent.
            for ((request, file) in listOf(boRequest to annOut, annRequest to boOut)) {
                val r = CliRun.run(s, op, "operator", "fulfil", request, "--sealed-file", file.path)
                assertEquals(2, r.code, r.out + r.err)
                assertTrue("another request" in r.err && "nothing was sent" in r.err, r.err)
            }
            // A bare sealed answer (the old tool's last line) is refused as well.
            val bare = File(tmp, "bare.txt").apply { writeText(annOut.readText().trim().lines().last().substringAfterLast(':') + "\n") }
            assertTrue("without its request" in CliRun.run(s, op, "operator", "fulfil", annRequest, "--sealed-file", bare.path).err)
            // Both still answerable: each at its own row, and each person's device then shows its own account to confirm.
            CliRun.run(s, op, "operator", "fulfil", annRequest, "--sealed-file", annOut.path).ok()
            CliRun.run(s, op, "operator", "fulfil", boRequest, "--sealed-file", boOut.path).ok()
            for (p in listOf(ann, bo)) {
                val check = CliRun.run(s, p.device, "recover", "assist", env = pw(newPw))
                assertEquals(2, check.code, check.err)
                assertTrue(check.out.contains("account ID ${p.accountId}"), check.out)
            }
            // And a recovery that works: Ann finishes, with a new password and kit.
            val done = CliRun.run(s, ann.device, "recover", "assist", "--account-id", ann.accountId, "--kit-out", File(tmp, "ann-new-kit.txt").path, env = pw(newPw))
            assertEquals(0, done.code, done.out + done.err)
            assertTrue(done.out.contains("recovered: ${ann.email}"), done.out)
        }
    }
}
