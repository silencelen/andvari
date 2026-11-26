package io.silencelen.andvari.core.client.deletion

import io.silencelen.andvari.core.client.account.Reauth
import io.silencelen.andvari.core.client.account.ReauthSession
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.pin.GatePin
import io.silencelen.andvari.core.client.pin.PinRoot
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountDeleteBlocker
import io.silencelen.andvari.core.model.wire.AccountDeletePreview
import io.silencelen.andvari.core.model.wire.AccountDeleteRequest
import io.silencelen.andvari.core.model.wire.DeleteMembership
import io.silencelen.andvari.core.model.wire.DeletedAtResponse
import io.silencelen.andvari.core.model.wire.LogHead
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.core.trust.Checked
import io.silencelen.andvari.core.trust.KnownHashes
import io.silencelen.andvari.core.trust.LogEntry
import io.silencelen.andvari.core.trust.MemberRole
import io.silencelen.andvari.core.trust.VaultLog
import io.silencelen.andvari.core.trust.VaultState
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Self-deletion with leaves (spec 03 §13, design §3.11, FS-R7) against an in-memory server. */
class WireAccountDeletionTest {
    private val crypto = createCryptoProvider()
    private val alice = "11111111-1111-4111-8111-111111111111"
    private val bob = "22222222-2222-4222-8222-222222222222"
    private val vaultId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    private val aliceSign = crypto.signKeypairFromSeed(ByteArray(32) { 3 })
    private val bobSign = crypto.signKeypairFromSeed(ByteArray(32) { 5 })
    private val bobBox = crypto.boxKeypairFromSeed(ByteArray(32) { 5 })
    private val origin = "https://h.example"
    private var now = 1_763_164_800_000L

    /** alice's vault with bob added: the log bob's leave must extend. */
    private val log: VaultState = buildLog(now - 5000)

    private fun buildLog(t0: Long): VaultState {
        val vk = ByteArray(32) { 9 }
        val g = LogEntry.Genesis(vaultId, alice, t0, Bytes.toB64(crypto.boxKeypairFromSeed(ByteArray(32) { 3 }).publicKey), VaultLog.vkCommit(crypto, vk, vaultId))
        val s0 = (VaultLog.signChecked(crypto, aliceSign, null, g) as Checked.Ok).value.step.state
        val add = LogEntry.Add(vaultId, 1, s0.head.hash, alice, t0 + 1000, bob, Bytes.toB64(bobBox.publicKey), MemberRole.WRITER, Bytes.toB64(ByteArray(16) { 1 }))
        return (VaultLog.signChecked(crypto, aliceSign, s0, add) as Checked.Ok).value.step.state
    }

    private inner class Server : WireClient {
        override val origin = this@WireAccountDeletionTest.origin
        var preview: AccountDeletePreview? = AccountDeletePreview(emptyList(), emptyList(), listOf(vaultId), listOf(DeleteMembership(vaultId, LogHead(log.head.seq, log.head.hash, log.at))), false)
        var answer: WireResult<String>? = null
        val deletes = ArrayList<AccountDeleteRequest>()
        var previews = 0

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> = when (route) {
            WireRoute.ACCOUNT_DELETE_PREVIEW -> previews++.let { preview }?.let { WireResult.Ok(decode(WireJson.json.encodeToString(AccountDeletePreview.serializer(), it)), 200) }
                ?: WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            WireRoute.ACCOUNT_DELETE -> {
                deletes += WireJson.json.decodeFromString(AccountDeleteRequest.serializer(), bodyJson!!)
                @Suppress("UNCHECKED_CAST")
                when (val a = answer) {
                    null -> WireResult.Ok(decode(WireJson.json.encodeToString(DeletedAtResponse.serializer(), DeletedAtResponse(now))), 200)
                    is WireResult.Ok -> WireResult.Ok(decode(a.value), 200)
                    else -> a as WireResult<T>
                }
            }
            else -> WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        }
    }

    private var wiped = 0
    private var derived = 0
    private var pins = listOf(GatePin(origin, PinRoot.TRUST_GATE))

    private fun deletion(server: Server, verified: VaultState? = null) = WireAccountDeletion(
        bob, "bob@x.example", bobSign, server, crypto,
        Reauth(object : ReauthSession {
            override val origin = this@WireAccountDeletionTest.origin
            override val emailNorm = "bob@x.example"
            override suspend fun deriveCurrentAuthKey(password: CharArray): String { derived++; return "K".repeat(43) }
        }, { pins }),
        { if (it == vaultId) verified else null }, { now }, { wiped++ },
    )

    @Test fun leavesAreSignedAtTheServedHeadAndVerifyThere() = runBlocking<Unit> {
        val server = Server()
        val outcome = deletion(server).delete(" Bob@X.example ", "pw".toCharArray(), null)
        assertEquals(DeletionOutcome.Deleted(now), outcome)
        assertEquals(1, wiped)
        val sent = server.deletes.single()
        assertEquals("K".repeat(43), sent.currentAuthKey)
        val frame = Bytes.fromB64(sent.leaves.single())
        val step = assertIs<Checked.Ok<*>>(VaultLog.verify(crypto, vaultId, log, frame, KnownHashes.NONE_HELD), "the leave extends the served head")
        val entry = assertIs<LogEntry.Leave>(VaultLog.parse(crypto, frame).valueOrNull()!!.entry)
        assertEquals(log.head.seq + 1, entry.seq)
        assertEquals(bob, entry.actor)
        assertEquals(maxOf(now, log.at), entry.at, "at = max(device clock, head.at)")
        assertNotNull(step)
    }

    @Test fun aFarFutureUnverifiedHeadSignsNothing() = runBlocking<Unit> {
        val server = Server()
        val day = WireAccountDeletion.FUTURE_LIMIT_MS
        server.preview = server.preview!!.copy(memberships = listOf(DeleteMembership(vaultId, LogHead(log.head.seq, log.head.hash, now + day + 1))))
        assertEquals(DeletionOutcome.FutureHead, deletion(server).delete("bob@x.example", "pw".toCharArray(), null))
        assertTrue(server.deletes.isEmpty(), "nothing signed is sent")
        // Exactly one day ahead is still allowed; at = head.at then.
        server.preview = server.preview!!.copy(memberships = listOf(DeleteMembership(vaultId, LogHead(log.head.seq, log.head.hash, now + day))))
        assertIs<DeletionOutcome.Deleted>(deletion(server).delete("bob@x.example", "pw".toCharArray(), null))
        val leave = VaultLog.parse(crypto, Bytes.fromB64(server.deletes.single().leaves.single())).valueOrNull()!!.entry
        assertEquals(now + day, leave.at)
    }

    @Test fun aVerifiedHeadIsNotHeldToTheOneDayRule() {
        val server = Server()
        val far = buildLog(now + 3 * WireAccountDeletion.FUTURE_LIMIT_MS)
        val m = listOf(DeleteMembership(vaultId, LogHead(far.head.seq, far.head.hash, far.at)))
        assertNotNull(deletion(server, verified = far).leaves(m, now), "this device verified that head itself")
        assertNull(deletion(server, verified = null).leaves(m, now))
    }

    @Test fun aVerifiedHeadIsSignedAfterAtItsVerifiedAtNotTheServedOne() = runBlocking<Unit> {
        // The device verified {seq, hash, at = log.at}; the preview names that head with a far-future `at`.
        val server = Server()
        val hostileAt = (1L shl 53) - 1
        server.preview = server.preview!!.copy(memberships = listOf(DeleteMembership(vaultId, LogHead(log.head.seq, log.head.hash, hostileAt))))
        assertIs<DeletionOutcome.Deleted>(deletion(server, verified = log).delete("bob@x.example", "pw".toCharArray(), null))
        val frame = Bytes.fromB64(server.deletes.single().leaves.single())
        val leave = VaultLog.parse(crypto, frame).valueOrNull()!!.entry
        assertEquals(maxOf(now, log.at), leave.at, "the leave's at comes from the verified head, never the served at")
        assertIs<Checked.Ok<*>>(VaultLog.verify(crypto, vaultId, log, frame, KnownHashes.NONE_HELD), "and it still extends the verified head")
        // The same served `at` beside a head this device did NOT verify is refused by the one-day bound.
        val s2 = Server()
        s2.preview = server.preview
        assertEquals(DeletionOutcome.FutureHead, deletion(s2, verified = null).delete("bob@x.example", "pw".toCharArray(), null))
        assertTrue(s2.deletes.isEmpty())
    }

    /**
     * The typed address is checked before anything else; then the password is proven on the device (spec 01 §7),
     * before the preview is fetched or a leave signed. Every early exit wipes the password it was
     * handed.
     */
    @Test fun aTypoIsCheckedFirstThenThePasswordAndEveryEarlyExitWipesIt() = runBlocking<Unit> {
        val server = Server()
        fun pw() = "pw".toCharArray()
        fun wiped(a: CharArray) = assertTrue(a.all { it == '\u0000' }, "the password is wiped")
        pw().let { assertEquals(DeletionOutcome.EmailMismatch, deletion(server).delete("someone@x.example", it, null)); wiped(it) }
        assertEquals(0, derived, "a typo derives nothing")
        server.preview = server.preview!!.copy(blockers = listOf(AccountDeleteBlocker("shared_vault", vaultId, 2)))
        pw().let { assertIs<DeletionOutcome.Blocked>(deletion(server).delete("bob@x.example", it, null)); wiped(it) }
        server.preview = server.preview!!.copy(blockers = emptyList(), totpRequired = true)
        pw().let { assertEquals(DeletionOutcome.TotpNeeded, deletion(server).delete("bob@x.example", it, null)); wiped(it) }
        server.preview = null
        pw().let { assertEquals(DeletionOutcome.Unreachable, deletion(server).delete("bob@x.example", it, "123456")); wiped(it) }
        assertTrue(server.deletes.isEmpty())
        // A forked origin refuses the re-authentication itself: nothing derived.
        val before = derived
        val s2 = Server()
        pins = listOf(GatePin(origin, PinRoot.TRUST_GATE, blocked = true))
        pw().let { assertEquals(DeletionOutcome.ReauthRefused, deletion(s2).delete("bob@x.example", it, null)); wiped(it) }
        assertTrue(s2.deletes.isEmpty())
        assertEquals(before, derived)
    }

    /** A password this device's wrap refuses (the session's proof): no preview is fetched, no leave signed, nothing sent. */
    @Test fun aWrongPasswordFetchesSignsAndSendsNothing() = runBlocking<Unit> {
        val server = Server()
        val d = WireAccountDeletion(
            bob, "bob@x.example", bobSign, server, crypto,
            Reauth(object : ReauthSession {
                override val origin = this@WireAccountDeletionTest.origin
                override val emailNorm = "bob@x.example"
                override suspend fun deriveCurrentAuthKey(password: CharArray): String? = null
                override suspend fun proveCurrentAuthKey(password: CharArray) = io.silencelen.andvari.core.client.account.ReauthKey.WrongPassword
            }, { pins }),
            { null }, { now }, { wiped++ },
        )
        val pw = "wrong".toCharArray()
        assertEquals(DeletionOutcome.WrongPassword, d.delete("bob@x.example", pw, null))
        assertTrue(pw.all { it == '\u0000' })
        assertEquals(0, server.previews, "no preview fetched")
        assertTrue(server.deletes.isEmpty())
    }

    @Test fun answersMapAndOnlyA200Wipes() = runBlocking<Unit> {
        fun refused(status: Int, code: String, vaultIds: List<String>? = null, blockers: List<AccountDeleteBlocker>? = null) =
            WireResult.Refused(status, WireError(code, "m", vaultIds = vaultIds, blockers = blockers))
        val cases = listOf(
            refused(409, "account_delete_log_stale", vaultIds = listOf(vaultId)) to DeletionOutcome.LogStale(listOf(vaultId)),
            refused(409, "account_delete_blocked", blockers = listOf(AccountDeleteBlocker("operator", null, 0))) to DeletionOutcome.Blocked(listOf(AccountDeleteBlocker("operator", null, 0))),
            refused(400, "at_ahead") to DeletionOutcome.ClockAhead,
            refused(400, "bad_totp_code") to DeletionOutcome.BadTotp,
            // The server's refusal of the proof: never the wrong password a local proof answers.
            refused(403, "reauth_failed") to DeletionOutcome.Refused(io.silencelen.andvari.core.client.account.Reauthed.PROOF_REFUSED),
            refused(401, "credential_changed") to DeletionOutcome.Refused("credential_changed"),
            refused(503, "unavailable") to DeletionOutcome.Unknown,
            WireResult.NoAnswer(NoAnswerKind.TIMEOUT) to DeletionOutcome.Unknown,
        )
        for ((answer, expected) in cases) {
            val server = Server()
            server.answer = answer
            assertEquals(expected, deletion(server).delete("bob@x.example", "pw".toCharArray(), null), answer.toString())
        }
        assertEquals(0, wiped, "nothing wiped on any answer but 200")
    }
}
