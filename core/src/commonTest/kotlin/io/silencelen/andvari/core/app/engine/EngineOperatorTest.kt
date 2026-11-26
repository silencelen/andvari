package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.DisableWhy
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.OperatorDeleteWhy
import io.silencelen.andvari.core.app.OperatorResult
import io.silencelen.andvari.core.app.QuotaLimits
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.account.CardServer
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.KeyPairBytes
import io.silencelen.andvari.core.trust.CardFields
import io.silencelen.andvari.core.trust.InstanceCard
import io.silencelen.andvari.core.trust.InstanceKind
import io.silencelen.andvari.core.trust.RecoveryRotation
import io.silencelen.andvari.core.trust.RotationFields
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.AccountSummary
import io.silencelen.andvari.core.model.wire.AdminEscrowResponse
import io.silencelen.andvari.core.model.wire.AdminMailStatus
import io.silencelen.andvari.core.model.wire.AdminPolicy
import io.silencelen.andvari.core.model.wire.AdminRecoveryRequest
import io.silencelen.andvari.core.model.wire.AdminSignupPolicy
import io.silencelen.andvari.core.model.wire.AdminSignupStatus
import io.silencelen.andvari.core.model.wire.AdminStatus
import io.silencelen.andvari.core.model.wire.AuditRow
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.Quota
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The operator views on the engine (design §9.2): the desktop's console over the
 * admin routes, each view against a server that lies in the ways that view can be lied to, every † route behind the
 * local proof (a wrong password sends no request), and a lock that overtakes an intent.
 */
class EngineOperatorTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val bob = "22222222-2222-4222-8222-222222222222"
    private val bobsPhone = "33333333-3333-4333-8333-333333333333"
    private val request = "AAAAAAAAAAAAAAAAAAAAAA"

    /** The request's key, and the token `recovery-cli assist` prints for it (spec 04 §7 step 3; the engine never opens the seal). */
    private val requestKey = Bytes.toB64(ByteArray(32) { 3 })
    private val token = io.silencelen.andvari.core.trust.AnswerToken.format(request, requestKey, "ab".repeat(32),
        ByteArray(io.silencelen.andvari.core.trust.AnswerToken.sealedBytes("bob@example.com")) { 7 })

    /**
     * The admin routes (spec 03 §7) over [inner]: what they serve is set per test; every † body's proof is checked. Every
     * other route goes to [next] (the card routes of spec 03 §17 as [CardServer] answers them). [hold] stops the first
     * call of its route, of any route, until [release].
     */
    private class Admin(val inner: FakeInstance, val next: WireClient) : WireClient by inner {
        val calls = ArrayList<Pair<WireRoute, String>>()
        var accounts: List<AccountSummary> = emptyList()
        var userCount: Long? = null
        var devicePage: (String?) -> List<Device> = { emptyList() }
        var audit: List<AuditRow> = emptyList()
        var requests: List<AdminRecoveryRequest> = emptyList()
        var hold: WireRoute? = null

        /** The code the next `PUT /admin/policy` is refused with (`400`), once; null: stored. */
        var refusePolicy: String? = null

        /** When true, a card the server stores is not served ([hidden] of the newest are left out of `GET /instance`). */
        var hideStored = false
        var hidden = 0
        val reached = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()

        private fun <T> ok(text: String, decode: (String) -> T): WireResult<T> = WireResult.Ok(decode(text), 200)

        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == hold) {
                hold = null
                reached.complete(Unit)
                release.await()
            }
            if (route == WireRoute.INSTANCE && hidden > 0) {
                // The cards stored since [hideStored] was set are kept, and not served.
                val raw = next.call(route, pathParams, query, bodyJson, authenticated) { it }
                if (raw !is WireResult.Ok) return next.call(route, pathParams, query, bodyJson, authenticated, decode)
                val served = WireJson.json.decodeFromString(io.silencelen.andvari.core.model.wire.InstanceResponse.serializer(), raw.value)
                val cut = served.copy(cards = served.cards.dropLast(hidden))
                return ok(WireJson.json.encodeToString(io.silencelen.andvari.core.model.wire.InstanceResponse.serializer(), cut), decode)
            }
            if (route == WireRoute.INSTANCE_CARD_PUT && hideStored) {
                val r = next.call(route, pathParams, query, bodyJson, authenticated, decode)
                if (r is WireResult.Ok) hidden++
                return r
            }
            if (!route.name.startsWith("ADMIN_")) return next.call(route, pathParams, query, bodyJson, authenticated, decode)
            calls += route to (bodyJson ?: query.orEmpty())
            if (bodyJson != null) {
                val key = (WireJson.json.parseToJsonElement(bodyJson) as JsonObject)["currentAuthKey"]?.jsonPrimitive?.content
                if (inner.accounts.values.none { it.authKey == key }) return WireResult.Refused(403, WireError("reauth_failed", "x"))
            }
            val j = WireJson.json
            if (route == WireRoute.ADMIN_POLICY_PUT) refusePolicy?.let { code ->
                refusePolicy = null
                return WireResult.Refused(400, WireError(code, "the server's own message for $code"))
            }
            return when (route) {
                WireRoute.ADMIN_ACCOUNTS -> ok(j.encodeToString(ListSerializer(AccountSummary.serializer()), accounts), decode)
                WireRoute.ADMIN_STATUS -> ok(j.encodeToString(AdminStatus.serializer(), AdminStatus("1.0.0", 0, userCount ?: accounts.size.toLong(), 0, 0, 0, 0, 0, false, true,
                    "private", AdminSignupStatus("open", 200, 1, false), AdminMailStatus(false))), decode)
                WireRoute.ADMIN_POLICY_GET, WireRoute.ADMIN_POLICY_PUT -> ok(j.encodeToString(AdminPolicy.serializer(), policy()), decode)
                WireRoute.ADMIN_RECOVERY_REQUESTS -> ok(j.encodeToString(ListSerializer(AdminRecoveryRequest.serializer()), requests), decode)
                WireRoute.ADMIN_ACCOUNT_DEVICES -> ok(j.encodeToString(ListSerializer(Device.serializer()), devicePage(query?.substringAfter("after=", "")?.ifEmpty { null })), decode)
                WireRoute.ADMIN_AUDIT -> ok(j.encodeToString(ListSerializer(AuditRow.serializer()), audit), decode)
                WireRoute.ADMIN_ACCOUNT_DELETE -> ok("""{"deletedAt":1}""", decode)
                WireRoute.ADMIN_QUOTA -> ok(j.encodeToString(Quota.serializer(), Quota(1, 2, 3, 4)), decode)
                WireRoute.ADMIN_ESCROW -> ok(j.encodeToString(AdminEscrowResponse.serializer(), AdminEscrowResponse(pathParams.getValue("userId"), "c2VhbGVk", "c2VlZA", "aWQ")), decode)
                else -> ok("{}", decode)
            }
        }

        fun policy() = AdminPolicy(emptyMap(), KdfParams(), 300, 30, true, 3600, 30, 26_214_400, 67_108_864, Quota(104_857_600, 5000, 50, 20), AdminSignupPolicy(null, null))

        fun sent(): List<WireRoute> = calls.map { it.first }
    }

    private class Env(val server: FakeInstance, val admin: Admin, val transport: BearerTransport, val desk: EngineDesktopAppApi, val aliceSignKey: String)

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** A recovery key's Ed25519 pair, and the fingerprint of its X25519 image (design §2.3, §4.5). */
    private fun recoveryKey(seed: Int): Pair<KeyPairBytes, String> {
        val pair = crypto.signKeypairFromSeed(ByteArray(32) { seed.toByte() })
        return pair to Bytes.toHexLower(crypto.sha256(crypto.ed25519PkToCurve25519(pair.publicKey)))
    }

    /**
     * Alice registers on a phone, is made the operator, and signs in on the desktop: the console's session. With
     * [handOver], the server's card 1 (signed by its first operator) hands the instance to Alice's own signing key and
     * names recovery key 31, before the desktop pins it: Alice's desktop signs every card after it.
     */
    private suspend fun env(handOver: Boolean = false): Env {
        val server = FakeInstance(crypto)
        val admin = Admin(server, CardServer(crypto, server))
        val transport = BearerTransport(mapOf(server.origin to admin))
        fun engine(p: AppPlatform) = AppEngine(p, "Box", transport, MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now }, baked = null,
            storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined)
        val a = EngineAppApi(engine(AppPlatform.ANDROID)).also { it.linksFlow.answersPollMs = Long.MAX_VALUE; it.start() }
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        val alice = server.account("alice@example.com").userId
        server.operatorUserId = alice
        val aliceSignKey = Bytes.toB64(assertNotNull(a.keeper.established).account.signing.publicKey)
        if (handOver) {
            server.cards += InstanceCard.sign(crypto, server.operatorSign, CardFields(server.instanceId, 1, server.card0Hash, server.origin, "Home",
                InstanceKind.PRIVATE, alice, aliceSignKey, recoveryKey(31).second, server.now - 5_000))
        }

        val d = EngineDesktopAppApi(engine(AppPlatform.LINUX)).also { it.linksFlow.answersPollMs = Long.MAX_VALUE; it.start() }
        d.entry.openSignIn(d.at())
        d.entry.openPasswordSignIn(d.at())
        assertEquals(ServerResult.DONE, d.entry.chooseOwnServer(d.at(), "https://h.example"))
        assertEquals(ServerResult.DONE, d.entry.confirmTrustGate(d.at<EntryScreen.TrustGate>()))
        assertEquals(SignInAnswer.DONE, d.entry.submitSignIn(d.at(), "alice@example.com", strong))
        assertEquals(AppPhase.UNLOCKED, d.snapshot.phase)
        admin.accounts = listOf(summary(alice, "alice@example.com", "operator"), summary(bob, "bob@example.com", "member"))
        admin.devicePage = { after -> if (after == null) listOf(Device(bobsPhone, "android", "Bob's phone", "0.30.0", 1, 2, live = true, how = "registered")) else emptyList() }
        // A row of the wire's grammar (the app interface's row check), whose key the test's answer token names.
        admin.requests = listOf(AdminRecoveryRequest(request, bob, "bob@example.com", "0".repeat(32), requestKey, "android", 1, 2, 3))
        return Env(server, admin, transport, d, aliceSignKey)
    }

    /** The served chain as the shared verifiers verify it from card 0: its newest card. */
    private fun newest(e: Env): CardFields {
        val r = InstanceCard.verifyChain(crypto, e.server.cards)
        assertNull(r.verdict, "the served chain verifies")
        return r.chain.cards.last().fields
    }

    private fun cardRoutesSent(e: Env) = e.transport.sent.map { it.route }.filter { it == WireRoute.INSTANCE_CARD_PUT || it == WireRoute.INSTANCE_ROTATION_PUT }

    /**
     * The desktop app's need: a card signed and stored through the bound path, and the console shows
     * the new name at once, with no second read of the console.
     */
    /** The additive `escrowFingerprint` of a request row: absent or a hex64 key fingerprint; anything else fails the row's check. */
    @Test fun aRequestRowsEscrowFingerprintIsAbsentOrAHex64AndNothingElse() {
        val base = AdminRecoveryRequest(Bytes.toB64(ByteArray(16) { 1 }), "11111111-1111-4111-8111-111111111111", "bob@example.com", "0".repeat(32),
            Bytes.toB64(ByteArray(32) { 2 }), "android", 1, 2, 3)
        val good = base.copy(requestId = Bytes.toB64(ByteArray(16) { 3 }), escrowFingerprint = "ab".repeat(32))
        val bad = base.copy(requestId = Bytes.toB64(ByteArray(16) { 4 }), escrowFingerprint = "AB".repeat(32))
        val short = base.copy(requestId = Bytes.toB64(ByteArray(16) { 5 }), escrowFingerprint = "ab".repeat(16))
        val checked = assertNotNull(OperatorRows.requests(listOf(base, good, bad, short)))
        assertEquals(listOf(base.requestId, good.requestId), checked.rows.map { it.requestId })
        assertEquals(2, checked.bad)
    }

    /**
     * A request whose copy the server says is sealed to another recovery key than the pinned card's: the console says
     * that both sheets are needed, naming the outgoing key and the current one; no line when they match, when the server
     * sent no key, or when the pinned card names none. Before, nothing in the console said it.
     */
    @Test fun aRequestWhoseCopyIsSealedToAnOutgoingKeySaysBothSheetsAreNeeded() {
        val current = "cd".repeat(32)
        val outgoing = "ab".repeat(32)
        val base = AdminRecoveryRequest(Bytes.toB64(ByteArray(16) { 1 }), "11111111-1111-4111-8111-111111111111", "bob@example.com", "0".repeat(32),
            Bytes.toB64(ByteArray(32) { 2 }), "android", 1, 2, 3)
        fun console(fp: String?) = io.silencelen.andvari.core.app.OperatorConsole(
            io.silencelen.andvari.core.app.InstanceLabel("Home", "https://h.example", io.silencelen.andvari.core.app.ServerKind.PRIVATE_SERVER, selfNamed = false),
            io.silencelen.andvari.core.app.InstanceDetails("", 0L, ""), false, null, emptyList(), null, emptyList(), listOf(base), null, emptyList(),
            pinnedRecoveryFp = fp,
        )
        val line = assertNotNull(console(current).outgoingKeyLine(base.copy(escrowFingerprint = outgoing)))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.OPERATOR_COPY_ON_OUTGOING_KEY, line.key)
        assertEquals(listOf(outgoing, current), line.values)
        assertEquals(null, console(current).outgoingKeyLine(base.copy(escrowFingerprint = current)), "the same key: nothing to say")
        assertEquals(null, console(current).outgoingKeyLine(base), "no key sent")
        assertEquals(null, console(null).outgoingKeyLine(base.copy(escrowFingerprint = outgoing)), "no pin read")
        assertEquals(null, console("none").outgoingKeyLine(base.copy(escrowFingerprint = outgoing)), "the card names no recovery key")
    }

    @Test fun aRenameIsSignedAndStoredThroughTheBoundPathAndTheConsoleShowsItWithoutASecondRead() = runBlocking<Unit> {
        val e = env(handOver = true)
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        assertEquals("Home", assertNotNull(op.console).instance.name)
        val seen = ArrayList<String?>()
        val watching = op.observeConsole { seen += it?.instance?.name }
        val reads = e.admin.calls.size
        assertEquals(OperatorResult.DONE, op.renameInstance("The Smiths", strong))
        assertEquals("The Smiths", assertNotNull(op.console).instance.name, "the console shows the card the pin followed")
        assertEquals("The Smiths", seen.last(), "and its observers were told")
        assertEquals(reads, e.admin.calls.size, "with no second read of the console")
        watching.close()
        // What the server stores is the card this account signed: card 2 after the card naming Alice's key.
        val card = newest(e)
        assertEquals(2, card.seq)
        assertEquals("The Smiths", card.name)
        assertEquals(e.aliceSignKey, card.operatorSignKey)
        assertEquals(listOf(WireRoute.INSTANCE_CARD_PUT), cardRoutesSent(e))
    }

    /**
     * A lock inside the card signing answers STALE, never a throw, and what was signed is sent whole or not at all: a lock
     * while the flow reads the chain (before anything is signed) sends nothing; a lock while the first rotation uploads
     * comes after the guard's check, so the card signed before the lock is stored too.
     */
    @Test fun aLockInsideTheCardSigningIsStaleAndWhatWasSignedIsSentWholeOrNotAtAll() = runBlocking<Unit> {
        val (seedA, fpA) = recoveryKey(31)
        val fpB = recoveryKey(32).second
        // Before anything is signed: the lock lands while the card flow refreshes the pin.
        val e = env(handOver = true)
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        e.admin.hold = WireRoute.INSTANCE
        val renaming = async(start = CoroutineStart.UNDISPATCHED) { op.renameInstance("The Smiths", strong) }
        e.admin.reached.await()
        e.desk.lock()
        e.admin.release.complete(Unit)
        assertEquals(OperatorResult.STALE, renaming.await())
        assertEquals(2, e.server.cards.size, "no card stored")
        assertEquals(emptyList(), cardRoutesSent(e), "nothing signed is sent")

        // After the check: the lock lands while the first rotation uploads; the card signed before it follows.
        val f = env(handOver = true)
        val fop = f.desk.operatorApi
        assertEquals(OperatorResult.DONE, fop.openConsole())
        val rotation = RecoveryRotation.sign(crypto, seedA, RotationFields(f.server.instanceId, fpA, fpB, f.server.now))
        f.admin.hold = WireRoute.INSTANCE_ROTATION_PUT
        val rotating = async(start = CoroutineStart.UNDISPATCHED) { fop.changeRecoveryKey(fpB, Bytes.toB64(rotation), strong) }
        f.admin.reached.await()
        f.desk.lock()
        f.admin.release.complete(Unit)
        assertEquals(OperatorResult.STALE, rotating.await())
        assertEquals(listOf(WireRoute.INSTANCE_ROTATION_PUT, WireRoute.INSTANCE_CARD_PUT), cardRoutesSent(f), "all of what was signed")
        val card = newest(f)
        assertEquals(2, card.seq)
        assertEquals(fpB, card.recoveryFp, "the stored card names the rotated key, so no rotation is left that no card names")
        assertTrue(f.server.rotations.any { it.contentEquals(rotation) })
        assertNull(fop.console, "the lock closed the console")
    }

    private fun summary(id: String, email: String, role: String) =
        AccountSummary(id, email, email.substringBefore('@'), role, "active", 0, null, null, "private", 0, 0, 0, 1)

    @Test fun theConsoleIsBoundAndEveryViewAndActionReachesItsRoute() = runBlocking<Unit> {
        val e = env()
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        val c = assertNotNull(op.console)
        assertEquals(listOf("alice@example.com", "bob@example.com"), c.accounts.map { it.email })
        assertNotNull(c.status)
        assertNotNull(c.policy)
        assertEquals(listOf(request), c.recoveryRequests.map { it.requestId })
        assertFalse(c.countsDisagree)

        assertEquals(OperatorResult.DONE, op.disableAccount(bob, DisableWhy.ABUSE, strong))
        assertTrue(e.admin.calls.last { it.first == WireRoute.ADMIN_ACCOUNT_DISABLE }.second.contains("\"reason\":\"abuse\""))
        assertEquals(OperatorResult.DONE, op.enableAccount(bob, strong))
        // The delete's reason is a closed choice: absent for the 30-day rule, the one value for under the minimum age.
        assertEquals(OperatorResult.DONE, op.deleteAccount(bob, strong))
        assertFalse(e.admin.calls.last { it.first == WireRoute.ADMIN_ACCOUNT_DELETE }.second.contains("under_minimum_age"))
        assertEquals(OperatorResult.DONE, op.deleteAccountFor(bob, OperatorDeleteWhy.UNDER_MINIMUM_AGE, strong))
        assertTrue(e.admin.calls.last { it.first == WireRoute.ADMIN_ACCOUNT_DELETE }.second.contains("\"reason\":\"under_minimum_age\""))

        assertEquals(OperatorResult.DONE, op.openAccountDevices(bob))
        assertEquals(listOf(bobsPhone), assertNotNull(op.console).devices.map { it.deviceId })
        assertEquals(bob, op.console!!.devicesOfUserId)
        assertEquals(OperatorResult.DONE, op.revokeAccountDevice(bobsPhone, strong))
        assertEquals(OperatorResult.DONE, op.setAccountQuota(bob, QuotaLimits(1, null, null, null), strong))
        assertEquals(OperatorResult.DONE, op.savePolicy(e.admin.policy(), strong))
        e.admin.audit = listOf(AuditRow(1, 10, "operator_disable", bob))
        assertEquals(OperatorResult.DONE, op.loadAudit(0, null, null))
        assertEquals(1, op.console!!.audit.size)
        assertEquals(OperatorResult.DONE, op.downloadEscrow(bob, strong))
        assertEquals(bob, assertNotNull(op.takeEscrow()).userId)
        assertNull(op.takeEscrow(), "handed over once")
        assertEquals(OperatorResult.DONE, op.fulfilRecovery(request, token, strong))
        // The upload carries the token's parts (spec 03 §18.6).
        val sent = e.admin.calls.last { it.first == WireRoute.ADMIN_RECOVERY_FULFIL }.second
        assertTrue(""""requestKey":"$requestKey"""" in sent && """"commitHash":"${"ab".repeat(32)}"""" in sent && """"sealed":"${token.substringAfterLast(':')}"""" in sent, sent)
        op.closeConsole()
        assertNull(op.console)
    }

    /** Spec 01 §7, "a wrong password sends nothing": every † operator route proves the password on this device first; a wrong one sends nothing at all. */
    @Test fun aWrongPasswordSendsNoRequestForAnyOperatorRoute() = runBlocking<Unit> {
        val e = env()
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        assertEquals(OperatorResult.DONE, op.openAccountDevices(bob))
        val wrong = "not the password at all 3"
        val actions: List<Pair<String, suspend () -> OperatorResult>> = listOf(
            "disable" to { op.disableAccount(bob, DisableWhy.OTHER, wrong) },
            "enable" to { op.enableAccount(bob, wrong) },
            "delete" to { op.deleteAccountFor(bob, OperatorDeleteWhy.UNDER_MINIMUM_AGE, wrong) },
            "revoke a device" to { op.revokeAccountDevice(bobsPhone, wrong) },
            "quota" to { op.setAccountQuota(bob, QuotaLimits(null, null, null, null), wrong) },
            "policy" to { op.savePolicy(e.admin.policy(), wrong) },
            "escrow" to { op.downloadEscrow(bob, wrong) },
            "fulfil" to { op.fulfilRecovery(request, token, wrong) },
            "rename the instance" to { op.renameInstance("Another name", wrong) },
        )
        for ((name, act) in actions) {
            val before = e.transport.sent.size
            assertEquals(OperatorResult.WRONG_PASSWORD, act(), name)
            assertEquals(emptyList(), e.transport.sent.drop(before).map { it.route }, "$name: a wrong password sends no request at all")
        }
    }

    /** Each view, against a server that lies the ways that view can be lied to. */
    @Test fun aLyingServerCannotMakeAViewShowWhatItsOwnListContradicts() = runBlocking<Unit> {
        val e = env()
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        val shown = assertNotNull(op.console).accounts

        // One account twice, or an id outside its grammar: the list is refused whole, and what was shown stays.
        e.admin.accounts = shown + shown.last()
        assertEquals(OperatorResult.FAILED, op.refreshConsole())
        assertEquals(shown.map { it.userId }, op.console!!.accounts.map { it.userId })
        e.admin.accounts = shown + summary("not-a-uuid", "x@example.com", "member")
        assertEquals(OperatorResult.FAILED, op.refreshConsole())
        // A count that does not match its own list is said.
        e.admin.accounts = shown
        e.admin.userCount = 7
        assertEquals(OperatorResult.DONE, op.refreshConsole())
        assertTrue(op.console!!.countsDisagree)

        // An account that is not on the list: nothing is sent for it.
        val ghost = "44444444-4444-4444-8444-444444444444"
        var before = e.admin.calls.size
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, op.openAccountDevices(ghost))
        assertEquals(OperatorResult.NO_SUCH_ACCOUNT, op.disableAccount(ghost, DisableWhy.ABUSE, strong))
        assertEquals(before, e.admin.calls.size)

        // A devices list that never ends stops at its stated number of pages and shows nothing.
        var n = 0
        e.admin.devicePage = { _ -> List(500) { i -> Device("00000000-0000-4000-8000-" + (++n).toString().padStart(12, '0'), "android", "d$i", null, 1, 1, true, "registered") } }
        before = e.admin.calls.size
        assertEquals(OperatorResult.FAILED, op.openAccountDevices(bob))
        assertEquals(40, e.admin.calls.size - before, "the stated number of pages")
        assertNull(op.console!!.devicesOfUserId)
        // A row that claims to be this session's is not the account's list.
        e.admin.devicePage = { after -> if (after == null) listOf(Device(bobsPhone, "android", "P", null, 1, 1, true, "registered", current = true)) else emptyList() }
        assertEquals(OperatorResult.FAILED, op.openAccountDevices(bob))
        // A device not on show: nothing is sent.
        before = e.admin.calls.size
        assertEquals(OperatorResult.NO_SUCH_DEVICE, op.revokeAccountDevice(bobsPhone, strong))
        assertEquals(before, e.admin.calls.size)

        // The audit: more than a page, a row twice, or a row outside the filters asked.
        e.admin.audit = List(501) { AuditRow(it.toLong(), 10, "operator_quota") }
        assertEquals(OperatorResult.FAILED, op.loadAudit(0, null, null))
        e.admin.audit = listOf(AuditRow(1, 10, "operator_quota"), AuditRow(1, 11, "operator_quota"))
        assertEquals(OperatorResult.FAILED, op.loadAudit(0, null, null))
        e.admin.audit = listOf(AuditRow(1, 10, "operator_policy"))
        assertEquals(OperatorResult.FAILED, op.loadAudit(0, "operator_quota", null))
        assertEquals(OperatorResult.FAILED, op.loadAudit(11, null, null))
        assertTrue(op.console!!.audit.isEmpty())

        // Recovery requests: one twice is not taken; a request not on show is never fulfilled.
        e.admin.requests = e.admin.requests + e.admin.requests
        assertEquals(OperatorResult.DONE, op.refreshConsole())
        assertEquals(1, op.console!!.recoveryRequests.size, "the list shown before stays")
        before = e.admin.calls.size
        assertEquals(OperatorResult.REQUEST_NOT_READY, op.fulfilRecovery("BBBBBBBBBBBBBBBBBBBBBB", token, strong))
        assertEquals(before, e.admin.calls.size)
        // Spec 04 §7 step 3: text that is not this request's answer gets its own result,
        // never "the request is not ready", and nothing is derived or sent.
        val sealedPart = token.substringAfterLast(':')
        val other = io.silencelen.andvari.core.trust.AnswerToken.format("CCCCCCCCCCCCCCCCCCCCCA", requestKey, "ab".repeat(32), Bytes.fromB64(sealedPart))
        val otherKey = io.silencelen.andvari.core.trust.AnswerToken.format(request, Bytes.toB64(ByteArray(32) { 4 }), "ab".repeat(32), Bytes.fromB64(sealedPart))
        for ((text, want) in listOf(
            "" to OperatorResult.ANSWER_EMPTY,
            sealedPart to OperatorResult.ANSWER_BARE,
            """{"userId":"u","encryptedIdentitySeed":"s"}""" to OperatorResult.ANSWER_IS_THE_COPY,
            "Request code matches the request key." to OperatorResult.ANSWER_NOT_AN_ANSWER,
            other to OperatorResult.ANSWER_OTHER_REQUEST,
            otherKey to OperatorResult.ANSWER_OTHER_REQUEST_KEY,
            token.dropLast(40) to OperatorResult.ANSWER_CUT_SHORT,
            token + "AAAA" to OperatorResult.ANSWER_TOO_LONG,
        )) {
            assertEquals(want, op.fulfilRecovery(request, text, strong), text.take(40))
        }
        assertEquals(before, e.admin.calls.size, "nothing was sent for any of them")
    }

    /**
     * A card the server stored and does not serve is not "done": its own outcome,
     * and no second card is signed at that number until the server serves it (then the pin follows and the hold goes).
     * A change this device refuses is its own outcome, never the server's refusal. A typed fingerprint and a rotation
     * statement must agree: one that does not is refused before the password is used, and nothing is sent.
     */
    @Test fun aCardStoredButNotServedIsNotDoneAndARefusalHereIsNotTheServers() = runBlocking<Unit> {
        val (seedA, fpA) = recoveryKey(31)
        val fpB = recoveryKey(32).second
        val e = env(handOver = true)
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        assertEquals(fpA, op.console!!.pinnedRecoveryFp, "from this device's pin")
        assertEquals(e.server.instanceId, op.console!!.pinnedInstanceId)

        // Refused here: a rename to the name it has, nothing sent.
        assertEquals(OperatorResult.CARD_REFUSED_HERE, op.renameInstance("Home", strong))
        assertTrue(cardRoutesSent(e).isEmpty())

        // A rotation statement that leads to B, with C typed: refused before anything is sent.
        val rotation = io.silencelen.andvari.core.trust.RecoveryRotation.sign(crypto, seedA,
            io.silencelen.andvari.core.trust.RotationFields(e.server.instanceId, fpA, fpB, e.server.now))
        val statement = Bytes.toB64(rotation)
        assertEquals(OperatorResult.ROTATION_REFUSED, op.changeRecoveryKey(recoveryKey(33).second, statement, strong))
        assertEquals(OperatorResult.ROTATION_REFUSED, op.changeRecoveryKey("", statement, strong))
        assertTrue(cardRoutesSent(e).isEmpty(), "nothing sent")

        // Stored and not served.
        e.admin.hideStored = true
        assertEquals(OperatorResult.CARD_STORED_NOT_SHOWN, op.renameInstance("The Smiths", strong))
        assertTrue(op.console!!.cardStoredNotShown)
        val puts = cardRoutesSent(e).size
        assertEquals(OperatorResult.CARD_STORED_NOT_SHOWN, op.renameInstance("Another name", strong))
        assertEquals(puts, cardRoutesSent(e).size, "no second card signed at that number")
        // The server serves it now: the pin follows, and the next change is signed after it.
        e.admin.hideStored = false
        e.admin.hidden = 0
        assertEquals(OperatorResult.DONE, op.renameInstance("Another name", strong))
        assertFalse(op.console!!.cardStoredNotShown)
        assertEquals(3, newest(e).seq)
    }

    /**
     * Request rows are checked field by field where they are read, before a screen or a clipboard
     * gets them. A request key with a line end and a command after it, a request code in the platform field, an address
     * that is not normalised, a server account ID that is not 32 hex: each row is not shown, and the console says the
     * server sent something it should not have. An account with an address outside the grammar is not shown; a display
     * or device name with a direction override is blanked, the row kept.
     */
    @Test fun rowsTheServerShouldNotHaveSentNeverReachTheScreen() = runBlocking<Unit> {
        val e = env()
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        assertFalse(op.console!!.serverSentBadRows)
        val good = e.admin.requests.single()
        fun id(n: Int) = Bytes.toB64(ByteArray(16) { (n + 40).toByte() })
        e.admin.requests = listOf(
            good,
            good.copy(requestId = id(1), rPub = good.rPub.dropLast(1) + "\nrm -rf ~"),
            good.copy(requestId = id(2), platform = "code 123 456"),
            good.copy(requestId = id(3), email = "Bob@Example.com"),
            good.copy(requestId = id(4), accountId = "Z".repeat(32)),
            good.copy(requestId = id(5), rPub = "AAAA"),
        )
        val bobRow = e.admin.accounts.single { it.userId == bob }
        e.admin.accounts = e.admin.accounts.map { if (it.userId == bob) it.copy(displayName = "Bob\u202Eevil") else it } +
            summary("55555555-5555-4555-8555-555555555555", "Eve@Example.com", "member")
        assertEquals(OperatorResult.DONE, op.refreshConsole())
        val c = assertNotNull(op.console)
        assertEquals(listOf(good.requestId), c.recoveryRequests.map { it.requestId }, "only the row that holds")
        assertTrue(c.serverSentBadRows)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.OPERATOR_SERVER_SENT_BAD_ROWS, c.serverSentBadRowsLine)
        assertTrue(c.accounts.none { it.userId == "55555555-5555-4555-8555-555555555555" }, "an address outside the grammar is not shown")
        assertEquals("", c.accounts.single { it.userId == bob }.displayName, "a name with a direction override is blanked")
        assertEquals(bobRow.email, c.accounts.single { it.userId == bob }.email)

        e.admin.devicePage = { after ->
            if (after == null) listOf(Device(bobsPhone, "android", "Bob\u200Bphone", "0.30.0", 1, 2, live = true, how = "registered"),
                Device("66666666-6666-4666-8666-666666666666", "toaster", "T", null, 1, 2, live = true, how = "registered")) else emptyList()
        }
        assertEquals(OperatorResult.DONE, op.openAccountDevices(bob))
        val devices = op.console!!.devices
        assertEquals(listOf(bobsPhone), devices.map { it.deviceId }, "a platform outside the closed list is not shown")
        assertEquals("", devices.single().name)
    }

    /** A lock while an action waits for the server: the console closes and the action answers its own STALE. */
    @Test fun aLockThatOvertakesAnOperatorActionClosesTheConsoleAndTheActionIsStale() = runBlocking<Unit> {
        val e = env()
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        e.admin.hold = WireRoute.ADMIN_ACCOUNT_DISABLE
        val pending = async(start = CoroutineStart.UNDISPATCHED) { op.disableAccount(bob, DisableWhy.REQUEST, strong) }
        e.admin.reached.await()
        e.desk.lock()
        assertNull(op.console, "a lock closes the console")
        e.admin.release.complete(Unit)
        assertEquals(OperatorResult.STALE, pending.await())
        assertEquals(OperatorResult.STALE, op.refreshConsole(), "nothing open")
        // A rename the lock overtook answers STALE too, never a throw.
        assertEquals(OperatorResult.STALE, op.renameInstance("New name", strong))
    }

    /**
     * The operator is told why a policy was refused, by the server's reason, beside the policy: a key cost below the
     * server's floor, a field outside its bounds; the next stored save and a lock clear it. Before: BAD_POLICY alone, the
     * reason dropped.
     */
    @Test fun aRefusedPolicySaysWhyByTheServersReasonUntilAStoredSaveOrALock() = runBlocking<Unit> {
        val e = env(handOver = true)
        val op = e.desk.operatorApi
        assertEquals(OperatorResult.DONE, op.openConsole())
        assertNull(assertNotNull(op.console).policyRefusal)
        e.admin.refusePolicy = "kdf_too_weak"
        assertEquals(OperatorResult.BAD_POLICY, op.savePolicy(e.admin.policy(), strong))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_KDF_TOO_WEAK, assertNotNull(op.console?.policyRefusal).key)
        e.admin.refusePolicy = "bad_session_ttl"
        assertEquals(OperatorResult.BAD_POLICY, op.savePolicy(e.admin.policy(), strong))
        assertEquals(io.silencelen.andvari.core.app.CopyKey.OPERATOR_POLICY_OUT_OF_BOUNDS, assertNotNull(op.console?.policyRefusal).key)
        assertEquals(OperatorResult.DONE, op.savePolicy(e.admin.policy(), strong))
        assertNull(assertNotNull(op.console).policyRefusal, "a stored save clears it")
        e.admin.refusePolicy = "kdf_too_weak"
        assertEquals(OperatorResult.BAD_POLICY, op.savePolicy(e.admin.policy(), strong))
        assertNotNull(op.console?.policyRefusal)
        e.desk.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, e.desk.unlock(assertNotNull(e.desk.snapshot.locked), strong))
        assertEquals(OperatorResult.DONE, op.openConsole())
        assertNull(assertNotNull(op.console).policyRefusal, "a lock clears it")
    }
}
