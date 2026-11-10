package io.silencelen.andvari.core.client.session

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpResponseData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.client.Tokens
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.MemberRecovery
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlinx.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Step 7: the §F.9 recovery capture, its piece-binding confirm, and the enroll path's confirm. */
class RecoveryCaptureTest {
    private val crypto = createCryptoProvider()
    private val session = VaultSession(FakeClocks())
    private val capture = RecoveryCapture(session)
    private val headers = headersOf(HttpHeaders.ContentType, "application/json")

    private var setupAnswer: suspend MockRequestHandleScope.() -> HttpResponseData = { respond("""{"pieceId":"p2"}""", HttpStatusCode.OK, headers) }
    private var confirmAnswer: suspend MockRequestHandleScope.() -> HttpResponseData = { respond("{}", HttpStatusCode.OK, headers) }
    private var seenSetup: String? = null

    private val api = AndvariApi(
        "https://home.example",
        HttpClient(
            MockEngine { request ->
                val path = request.url.encodedPath
                when {
                    path.endsWith("/recovery/self-setup") -> {
                        seenSetup = (request.body as io.ktor.http.content.OutgoingContent.ByteArrayContent).bytes().decodeToString()
                        setupAnswer()
                    }
                    path.endsWith("/recovery/self/confirm") -> confirmAnswer()
                    else -> respond("""{"error":"not_found","message":"no"}""", HttpStatusCode.NotFound, headers)
                }
            },
        ),
        Tokens("a", "r"),
    )

    private val account: Account = run {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        Account.enroll("invite", "u@example.com", "u", "pw", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "device", crypto).account
    }

    private fun live(): VaultSession.Unlocked {
        session.bind(api, account, SyncEngine(api, account, InMemoryVaultCache()))
        return session.get()!!
    }

    private val stale: suspend MockRequestHandleScope.() -> HttpResponseData =
        { respond("""{"error":"recovery_piece_stale","message":"replaced"}""", HttpStatusCode.Conflict, headers) }

    @Test
    fun aCommittedPieceIsHandedOverWithItsBinding() = runBlocking<Unit> {
        val r = assertIs<CaptureSetup.Ready>(capture.setup(live(), "fresh-auth-key"))
        assertEquals("p2", r.pieceId)
        assertFalse(r.secret.all { it == 0.toByte() })
        assertTrue(seenSetup!!.contains("fresh-auth-key"), "the fresh reauth rides the commit")
        assertTrue(MemberRecovery.confirmMatches(r.secret, MemberRecovery.displayForm(r.secret)), "the piece the reveal shows")
    }

    @Test
    fun aCommitThatFailsSaysWhyWithoutTheSecret() = runBlocking<Unit> {
        val live = live()
        setupAnswer = { throw IOException("unreachable") }
        assertEquals(CaptureSetup.Failed(offline = true), capture.setup(live, "k"))
        setupAnswer = { respond("""{"error":"server_error","message":"boom"}""", HttpStatusCode.InternalServerError, headers) }
        assertEquals(CaptureSetup.Failed(offline = false), capture.setup(live, "k"))
        setupAnswer = { respond("""{"error":"upgrade_required","message":"update"}""", HttpStatusCode.UpgradeRequired, headers) }
        assertEquals(CaptureSetup.UpgradeRequired, capture.setup(live, "k"))
    }

    @Test
    fun aSessionThatEndedMidCommitGetsNoPhrase() = runBlocking<Unit> {
        val live = live()
        setupAnswer = {
            session.lock() // a lock (or a sign-out) tore the session down while the commit ran
            respond("""{"pieceId":"p2"}""", HttpStatusCode.OK, headers)
        }
        assertEquals(CaptureSetup.SessionEnded, capture.setup(live, "k"))
    }

    @Test
    fun aLockedAccountCommitsNothing() = runBlocking<Unit> {
        val live = live()
        session.lock() // the account's keys are wiped: no piece is ever made from them
        assertEquals(CaptureSetup.SessionEnded, capture.setup(live, "k"))
        assertEquals(null, seenSetup, "nothing reached the server")
    }

    @Test
    fun theGatesConfirmIsAwaitedAndItsVerdictsAreKeptApart() = runBlocking<Unit> {
        val live = live()
        assertEquals(CaptureConfirm.Confirmed, capture.confirm(live, "p2"))
        confirmAnswer = stale
        assertEquals(CaptureConfirm.Stale, capture.confirm(live, "p2"), "§3: the phrase just typed is dead")
        confirmAnswer = { respond("""{"error":"server_error","message":"boom"}""", HttpStatusCode.InternalServerError, headers) }
        assertEquals(CaptureConfirm.Failed, capture.confirm(live, "p2"))
        confirmAnswer = { session.lock(); respond("{}", HttpStatusCode.OK, headers) }
        assertEquals(CaptureConfirm.SessionEnded, capture.confirm(live, "p2"), "never navigate a torn-down session")
    }

    @Test
    fun theEnrollPathsConfirmReportsAStalePiece() = runBlocking<Unit> {
        assertEquals(CaptureConfirm.Confirmed, capture.confirmEnrolled(api, "piece-1"))
        confirmAnswer = stale
        assertEquals(CaptureConfirm.Stale, capture.confirmEnrolled(api, "piece-1"))
        confirmAnswer = { throw IOException("unreachable") }
        assertEquals(CaptureConfirm.Failed, capture.confirmEnrolled(api, "piece-1"))
    }
}
