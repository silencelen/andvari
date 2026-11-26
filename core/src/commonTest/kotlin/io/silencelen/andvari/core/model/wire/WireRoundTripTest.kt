package io.silencelen.andvari.core.model.wire

import io.silencelen.andvari.core.crypto.KdfParams
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** One encode → decode round trip per wire type of spec 03, plus the shape rules the encoding must keep. */
class WireRoundTripTest {
    private val u1 = "0b6f3c2e-4d5a-4b7c-8d9e-0f1a2b3c4d5e"
    private val u2 = "1c7f4d3e-5e6b-4c8d-9e0f-1a2b3c4d5e6f"
    private val h64 = "a".repeat(64)
    private val b32 = "A".repeat(43)
    private val b16 = "B".repeat(22)
    private val kdf = KdfParams()
    private val keys = AccountKeys("salt", kdf, "wuvk", "eis", b32, true, PersonalWrap(u1, "wvk"), "genesisframe")
    private val head = LogHead(3, h64, 1_763_164_800_000)

    private inline fun <reified T> rt(v: T): String {
        val s = WireJson.json.encodeToString(v)
        assertEquals(v, WireJson.json.decodeFromString<T>(s), s)
        return s
    }

    @Test fun instanceAndPolicy() {
        rt(ClientPolicy(mapOf("android" to "1.0.0"), kdf, 300, 30, true, 3600, 30, 1, 2, 3, SignupPolicy(SignupMode.OPEN, false, true, 20), false, "andvari", "https://vault.andvaripass.com", null))
        rt(SignupPolicy(SignupMode.LINKS, true, false, 0))
        rt(InstanceResponse(listOf("c0", "c1"), listOf("r0")))
        val setup = rt(InstanceResponse(emptyList(), setup = InstanceSetup(u1, "https://a.example", "bmFtZQ", InstanceKind.PRIVATE, "none")))
        assertFalse("rotations" in WireJson.json.parseToJsonElement(setup).jsonObject, "setup form has no rotations")
        rt(InstanceSetup(u1, "https://a.example", "bmFtZQ", InstanceKind.PUBLIC, h64))
        rt(InstanceCardPut("frame", "cak"))
        rt(InstanceCardPutResponse(0, h64))
        rt(InstanceRotationPut("frame", "cak"))
    }

    @Test fun signupAndRegister() {
        rt(SignupStartRequest("A@b.example", true, SignupPow("2026-11-15", 12345)))
        rt(SignupStartRequest("a@b.example", false))
        rt(SignupPow("2026-11-15", 0))
        rt(SignupStartResponse(SignupStartResponse.SENT))
        rt(SignupVerifyRequest("a@b.example", "012345"))
        rt(SignupVerifyResponse(b32, 1))
        for (auth in listOf(RegisterAuth.Ticket(b32), RegisterAuth.Link(b16, b32, "env"), RegisterAuth.Enrol(b16, b32), RegisterAuth.Setup(b16, b32))) {
            val s = rt(RegisterRequest(auth, "a@b.example", "Me", u1, "salt", kdf, "ak", "wuvk", b32, "eis", "gen",
                PersonalVaultUpload(u2, "wvk", "meta"), PersonalWrap(u2, "wvk"), MemberRecoveryBlock("rw", "rak"),
                RecoveryChoice(RecoveryPosture.PRIVATE), true, NewDevice(WirePlatform.IOS, "phone", b32)))
            val a = WireJson.json.parseToJsonElement(s).jsonObject["auth"]!!.jsonObject
            assertEquals(setOf(auth.key), a.keys)
        }
        rt(PersonalVaultUpload(u1, "w", "m"))
        rt(PersonalWrap(u1, "w"))
        rt(MemberRecoveryBlock("rw", "rak"))
        rt(RecoveryChoice(RecoveryPosture.OPERATOR, EscrowUpload("sealed", h64)))
        rt(EscrowUpload("sealed", h64))
        rt(NewDevice(WirePlatform.LINUX, "desk", b32))
    }

    @Test fun registerAuthIsStrict() {
        fun dec(auth: String) = WireJson.json.decodeFromString(RegisterAuthSerializer, auth)
        assertEquals(RegisterAuth.Ticket("t"), dec("""{"signupTicket":"t"}"""))
        assertFailsWith<SerializationException> { dec("""{}""") }
        assertFailsWith<SerializationException> { dec("""{"signupTicket":"t","enrol":{"linkId":"l","registerToken":"r"}}""") }
        assertFailsWith<SerializationException> { dec("""{"invite":{"linkId":"l","registerToken":"r"}}""") }
        assertFailsWith<SerializationException> { dec("""{"signupTicket":5}""") }
        assertFailsWith<SerializationException> { dec("""{"link":{"linkId":"l","registerToken":"r"}}""") }
    }

    @Test fun sessions() {
        rt(PreloginRequest("a@b.example"))
        rt(PreloginResponse("salt", kdf))
        rt(LoginRequest("a@b.example", "ak", LoginDevice(WirePlatform.ANDROID, "p", b32, u1), "123456"))
        val s = rt(LoginRequest("a@b.example", "ak", LoginDevice(WirePlatform.ANDROID, "p", b32)))
        assertFalse("totp" in WireJson.json.parseToJsonElement(s).jsonObject, "an absent optional is left out")
        rt(LoginDevice(WirePlatform.WEB, "w", b32))
        rt(SessionResponse(u1, u2, "at", "rt", keys, AccountRole.MEMBER, false, false, "piece"))
        rt(SessionResponse(u1, u2, "at", "rt", keys.copy(personalWrap = null, genesis = null), AccountRole.OPERATOR, true, true))
        rt(RefreshRequest("rt"))
        rt(TokenPair("a", "r"))
        rt(TotpStatus(true, false))
        rt(TotpSetupRequest("123456", null))
        rt(TotpSetupRequest())
        rt(TotpSetupResponse("ABC", "otpauth://x"))
        rt(TotpCodeRequest("000000"))
        val disable = rt(TotpDisableRequest("000000", "cak"))
        assertTrue(""""currentAuthKey":"cak"""" in disable && """"code":"000000"""" in disable, "both fields are always sent")
        assertEquals(TotpDisableRequest::class, WireRoute.TOTP_DISABLE.request)
        assertEquals(Caller.SESSION_REAUTH, WireRoute.TOTP_DISABLE.caller, "turning two-step off is a password-proved route since 2026-11-16")
        rt(ReauthRequest("cak"))
    }

    @Test fun account() {
        rt(keys)
        val nullState = rt(AccountStateResponse(null, 0))
        assertTrue(""""sealedState":null""" in nullState, "a never-written state is an explicit null")
        rt(AccountStateResponse("env", 4))
        rt(AccountStatePut("env", 4))
        rt(PasswordChangeRequest("c", "n", "s", kdf, "w"))
        rt(AccountRecoveryPut(RecoveryPosture.OPERATOR, EscrowUpload("s", h64), "cak", AccountStatePut("env", 2)))
        rt(AccountRecoveryPut(RecoveryPosture.PRIVATE, null, "cak", AccountStatePut("env", 2)))
        rt(EscrowSelfPut("s", h64, listOf("r0", "r1")))
        rt(UsageResponse(null, 0))
        rt(UsagePut("u"))
        rt(Device(u1, WirePlatform.MACOS, "mac", "1.0.0", 1, null, true, DeviceHow.LINKED, u2, true))
        rt(Device(u1, WirePlatform.CLI, "cli", null, 1, 2, false, DeviceHow.PASSWORD))
        rt(RequireLinkPut(true, "cak"))
        rt(AccountDeleteBlocker(DeleteBlockerKind.SHARED_VAULT, u1, 2))
        rt(AccountDeleteBlocker(DeleteBlockerKind.OPERATOR, null, 0))
        rt(AccountDeletePreview(listOf(AccountDeleteBlocker("future_kind", null, 0)), listOf(u1), listOf(u2), listOf(DeleteMembership(u2, head)), true))
        rt(DeleteMembership(u1, head))
        rt(AccountDeleteRequest("a@b.example", "cak", null, listOf("leave")))
        rt(DeletedAtResponse(9))
        rt(RecoveryVerifyRequest("a@b.example", "rak"))
        rt(RecoveryVerifyResponse(u1, "t", "rw", "eis", b32))
        rt(RecoveryCommitRequest("t", "n", "s", kdf, "w", MemberRecoveryBlock("rw", "rak"), NewDevice(WirePlatform.WINDOWS, "pc", b32)))
        rt(RecoverySelfSetupRequest("cak", MemberRecoveryBlock("rw", "rak")))
        rt(RecoverySelfSetupResponse("piece"))
        rt(RecoverySelfConfirmRequest("piece"))
        assertEquals(RecoverySelfConfirmRequest(null), WireJson.json.decodeFromString<RecoverySelfConfirmRequest>("{}"))
    }

    @Test fun syncItemsEvents() {
        val item = SyncItem(u1, u2, 5, 1, 2, false, false, 2, listOf(u1), "blob")
        rt(SyncResponse(10, false, listOf(SyncVault(u1, VaultType.SHARED, 3, "m", 1, SyncLogHead(2, h64)), SyncVault(u2, VaultType.PERSONAL, 3, "m", 1)),
            listOf(SyncGrant(u1, u2, VaultRole.WRITER, "", 4, "sealedgrant")), listOf(item, item.copy(deleted = true, blob = null)),
            listOf(u2), listOf(RemovedGrantInfo(u2, RemovedReason.DELETED, 1, 2)), 1, 0))
        rt(SyncVault(u1, VaultType.SHARED, 1, "m", 1))
        rt(SyncLogHead(0, h64))
        rt(SyncGrant(u1, u2, VaultRole.OWNER, "wvk", 1))
        rt(item)
        rt(RemovedGrantInfo(u1, RemovedReason.LEFT))
        rt(PushRequest(listOf(Mutation(u1, MutationOp.PUT, u1, u2, 0, ItemUpload(2, emptyList(), "b")), Mutation(u2, MutationOp.DELETE, u1, u2, 3))))
        rt(Mutation(u1, MutationOp.DELETE, u1, u2, 1))
        rt(ItemUpload(2, listOf(u1), "b"))
        rt(PushResponse(11, listOf(MutationResult(u1, MutationStatus.CONFLICT, 11, item), MutationResult(u2, MutationStatus.REJECTED, reason = QuotaName.ACCOUNT_BYTES))))
        rt(MutationResult(u1, MutationStatus.APPLIED, 2))
        rt(ItemVersionsResponse(u1, listOf(ItemVersion(1, "b", 2, 3))))
        rt(ItemVersion(1, "b", 2, 3))
        rt(DeletedItemsResponse(listOf(DeletedItem(u1, u2, 3))))
        rt(DeletedItem(u1, u2, 3))
        rt(RevResponse(7))
        rt(AttachmentMeta(u1, u2, u1, 100, h64, 5))
        rt(EventsTicketResponse("t", 30))
        rt(EventFrame(EventFrame.REV, 42))
        assertEquals("""{"type":"revoked"}""", rt(EventFrame(EventFrame.REVOKED)))
    }

    @Test fun vaultLog() {
        rt(LogAppendRequest("entry", grant = "g"))
        rt(LogAppendRequest("entry", wrappedVk = "w", metaBlob = "m"))
        rt(LogAppendResponse(4, head))
        rt(LogPage(listOf("e0", "e1"), head))
        rt(LogPage(emptyList(), head, LogPurged(9)))
        rt(LogPage(emptyList(), head, deleted = LogDeleted(5, 9)))
        rt(LogAppendResponse(4, head, LogDeleted(5, 9)))
        rt(LogDeleted(5, 9))
        rt(LogPurged(1))
        rt(head)
        rt(VaultMemberSummary(u1, "a@b.example", "A", VaultRole.READER, b32, 1, "disabled"))
        rt(DeletedVaultSummary(u1, "m", "w", 1, 2, b16))
        rt(VaultMetaPut("m", 3))
        rt(VaultMetaPut("m"))
        rt(SelfWrapPut("w"))
        assertEquals(setOf("grant"), LogAppendRequest.sideFieldsFor(LogKind.ADD))
        assertEquals(setOf("metaBlob", "wrappedVk"), LogAppendRequest.sideFieldsFor(LogKind.GENESIS))
        assertEquals(setOf("wrappedVk"), LogAppendRequest.sideFieldsFor(LogKind.ACCEPT))
        assertEquals(emptySet(), LogAppendRequest.sideFieldsFor(LogKind.LEAVE))
        assertEquals(setOf("grant"), LogAppendRequest("e", grant = "g").presentSideFields())
    }

    @Test fun links() {
        rt(LinkCreateRequest(b16, LinkKind.REGISTER, "offer", 5, "t".repeat(43)))
        rt(LinkCreateRequest(b16, LinkKind.CONNECT, "offer", 5))
        rt(LinkCreatedResponse(5, 300_000))
        val open = LinkFetchResponse.open(LinkKind.ENROL, "offer", 9, null, null)
        rt(open)
        val openJson = open.toJsonObject()
        assertEquals(setOf("kind", "offer", "expiresAt", "state", "creatorUserId", "creatorIdentityPub", "reveal"), openJson.keys)
        assertEquals(open, WireJson.json.decodeFromString<LinkFetchResponse>(openJson.toString()))
        val answered = LinkFetchResponse.answered(LinkKind.CONNECT, b32)
        rt(answered)
        assertEquals(setOf("kind", "state", "reveal"), answered.toJsonObject().keys)
        assertTrue(""""reveal":null""" in WireJson.json.encodeToString(open), "reveal is always encoded")
        rt(LinkAnswerRequest("ans"))
        rt(LinkRevealRequest(b32))
        rt(LinkAnswer(b16, "ans", u1, 3))
        rt(DeviceLinkCreateRequest(b16, 5))
        val claim = DeviceLinkClaim(b32, "bmFtZQ", WirePlatform.IOS, h64, b32)
        rt(claim)
        rt(DeviceLinkView(DeviceLinkState.CLAIMED, 5, claim, b32, null))
        rt(DeviceLinkView(DeviceLinkState.OPEN, 5))
        rt(DeviceLinkNonceRequest(b32, h64))
        rt(DeviceLinkPollRequest(b32))
        rt(DeviceLinkPollResponse(DeviceLinkState.APPROVED, b32, "outer", b32))
        rt(DeviceLinkPollResponse(DeviceLinkState.CLAIMED))
        rt(DeviceLinkRevealRequest(b32, b32))
        rt(DeviceLinkApproveRequest("outer", "inner", b32))
        rt(DeviceLinkPickupRequest(b32, "ak", null, PickupDevice(b32)))
        rt(PickupDevice(b32))
        rt(DeviceLinkPickupResponse("inner", SessionResponse(u1, u2, "a", "r", keys, AccountRole.OPERATOR, true, false)))
    }

    @Test fun assistedRecoveryAndOperator() {
        rt(RecoveryRequestCreate("a@b.example", b32, h64, WirePlatform.ANDROID))
        rt(RecoveryRequestCreated(b16))
        rt(RecoveryRequestVerify("123456"))
        rt(RecoveryRequestVerified(RecoveryRequestState.HOLDING, 9))
        rt(RecoveryRequestSummary(b16, RecoveryRequestState.AWAITING_OPERATOR, 1, 2, 3, WirePlatform.IOS))
        rt(RecoveryVetoRequest("frame"))
        rt(RecoveryPollRequest(b32))
        rt(RecoveryPollResponse(RecoveryRequestState.HOLDING, 5))
        rt(RecoveryPollResponse(RecoveryRequestState.READY, null, "sealed", "eis", b32))
        rt(RecoveryRequestCommit(b32, "n", "s", kdf, "w", MemberRecoveryBlock("rw", "rak"), NewDevice(WirePlatform.IOS, "p", b32)))
        rt(AccountSummary(u1, "a@b.example", "A", AccountRole.MEMBER, AccountStatus.DISABLED, 1, null, 5, RecoveryPosture.PRIVATE, 10, 2, 1, 3))
        rt(AccountDisableRequest(DisableReason.ABUSE, "cak"))
        val q = rt(QuotaPut(null, 10, null, 5, "cak"))
        assertTrue(""""accountBytes":null""" in q, "a null quota limit is sent explicitly")
        val quota = Quota(1, 2, 3, 4)
        rt(quota)
        val policy = AdminPolicy(mapOf("ios" to "1.0.0"), kdf, 300, 30, true, 3600, 30, 1, 2, quota, AdminSignupPolicy(null, 100))
        rt(policy)
        rt(AdminSignupPolicy(SignupMode.CLOSED, null))
        val put = AdminPolicyPut.of(policy, "cak")
        rt(put)
        assertEquals(policy, put.policy())
        rt(AuditRow(1, 2, "login", u1, u2, "127.0.0.1", "m"))
        rt(AuditRow(1, 2, "login"))
        rt(AdminStatus("1.0.0", 1, 2, 3, 4, 5, 6, 7, true, true, InstanceKind.PUBLIC, AdminSignupStatus(SignupMode.OPEN, 200, 3, false), AdminMailStatus(true, 4)))
        rt(AdminSignupStatus(SignupMode.LINKS, 1, 1, true))
        rt(AdminMailStatus(false))
        rt(AdminRecoveryRequest(b16, u1, "a@b.example", "f".repeat(32), b32, WirePlatform.WEB, 1, 2, 3))
        rt(AdminEscrowResponse(u1, "s", "eis", b32))
        // The additive key fingerprints (2026-11-16): round-tripped when sent, absent when not.
        rt(AdminRecoveryRequest(b16, u1, "a@b.example", "f".repeat(32), b32, WirePlatform.WEB, 1, 2, 3, escrowFingerprint = "a".repeat(64)))
        rt(AdminEscrowResponse(u1, "s", "eis", b32, fingerprint = "a".repeat(64)))
        rt(RecoveryFulfilRequest("s", "cak"))
    }

    @Test fun errors() {
        rt(WireError(WireErrors.LOG_HEAD_MOVED, "m", seq = 3, hash = h64, at = 9))
        rt(WireError(WireErrors.QUOTA_EXCEEDED, "m", quota = QuotaName.OPEN_LINKS))
        rt(WireError(WireErrors.ACCOUNT_DELETE_BLOCKED, "m", blockers = listOf(AccountDeleteBlocker(DeleteBlockerKind.OPERATOR, null, 0))))
        rt(WireError(WireErrors.ACCOUNT_DELETE_LOG_STALE, "m", vaultIds = listOf(u1)))
        val plain = rt(WireError(WireErrors.BAD_REQUEST, "m"))
        assertEquals(setOf("error", "message"), WireJson.json.parseToJsonElement(plain).jsonObject.keys)
        assertEquals("bad_vault_id", WireErrors.badField("vaultId"))
        assertEquals("bad_meta_blob", WireErrors.badField("metaBlob"))
        assertEquals("hibp_upstream_503", WireErrors.hibpUpstream(503))
    }

    @Test fun unknownResponseFieldsAreIgnored() {
        val s = """{"rev":1,"head":{"seq":0,"hash":"$h64","at":1,"extra":true},"future":[1,2]}"""
        assertEquals(LogAppendResponse(1, LogHead(0, h64, 1)), WireJson.json.decodeFromString<LogAppendResponse>(s))
    }

    @Test fun routeTableIsComplete() {
        val routes = WireRoute.entries
        assertEquals(95, routes.size, "spec 03 §0.2: 95 HTTP routes")
        assertEquals(routes.size, routes.map { it.method to it.path }.toSet().size, "every (method, path) is unique")
        val rows = routes.map { it.row }.toSet()
        assertEquals((1..93).toSet() - 20, rows, "every index row but the retired 20")
        // Row 93 ends exactly one session: no bearer, the refresh token in the body, so not credential-free.
        assertEquals(WireRoute.REFRESH.request, WireRoute.END_SESSION.request)
        assertTrue(!WireRoute.END_SESSION.credentialFree && WireRoute.END_SESSION.caller == Caller.NONE)
        assertEquals(setOf(4, 5, 23, 29, 68, 69, 70, 71, 72, 84, 85, 86), routes.filter { it.refusedOnPublic }.map { it.row }.toSet())
        for (r in routes) {
            if (r.requestShape == BodyShape.JSON) assertTrue(r.request != null, "$r names its request type")
            if (r.responseShape == BodyShape.JSON) assertTrue(r.response != null, "$r names its response type")
        }
        assertEquals("/api/v1/vaults/$u1/log", WireRoute.LOG_APPEND.pathWith("vaultId" to u1))
    }

    // ---- strict decoders (spec 03 §16.6, §16.9): the wire has none of its own; these pin the shared verifiers' at this boundary ----

    private val bundle = io.silencelen.andvari.core.trust.DeviceLinkBundle(
        "https://vault.andvaripass.com", u1, io.silencelen.andvari.core.trust.Checkpoint(2, h64), u2, "a@b.example", b32, u1,
        listOf(io.silencelen.andvari.core.trust.BundleContact(u1, h64, 5)), listOf(io.silencelen.andvari.core.trust.BundleVault(u2, 7, h64)),
        io.silencelen.andvari.core.trust.Checkpoint(4, h64), 1_763_164_800_000,
    )

    private fun decodeBundle(t: String) = io.silencelen.andvari.core.trust.DeviceLink.decodeBundle(t.encodeToByteArray())
    private fun encodeBundle(b: io.silencelen.andvari.core.trust.DeviceLinkBundle) = io.silencelen.andvari.core.trust.DeviceLink.encodeBundle(b).decodeToString()

    @Test fun bundleRoundTripsAndIsStrict() {
        val text = encodeBundle(bundle)
        assertEquals(bundle, decodeBundle(text))
        fun bad(t: String) = assertNull(decodeBundle(t), t)
        bad(text.replaceFirst("{", """{"extra":1,"""))
        bad(text.replaceFirst(""""v":2""", """"v":"2""""))
        bad(text.replaceFirst(""""v":2""", """"v":2.0"""))
        bad(text.replaceFirst(""""v":2""", """"v":1"""))
        bad(text.replaceFirst(""""v":2,""", ""))
        bad(text.replaceFirst(""""v":2""", """"v":2,"v":2"""))
        bad(text.replaceFirst(u2, u2.uppercase()))
        bad(text.replaceFirst("https://vault.andvaripass.com", "https://vault.andvaripass.com/"))
        bad(text.replaceFirst("a@b.example", "A@b.example"))
        bad(text.replaceFirst(""""issuedAt":1763164800000""", """"issuedAt":-1"""))
        bad(text.replaceFirst(""""issuedAt":1763164800000""", """"issuedAt":9007199254740992"""))
        bad(text.replaceFirst(""""keyHash":"$h64"""", """"keyHash":"$h64","x":1"""))
        bad(text.replaceFirst(""""seq":2,""", """"seq":"2","""))
        val many = bundle.copy(contacts = List(1001) { io.silencelen.andvari.core.trust.BundleContact(u1, h64, 1) })
        assertFalse(io.silencelen.andvari.core.trust.DeviceLink.fits(many))
        // 1000 contacts exceed 64 KiB on their own, so the byte cap is the binding limit in practice.
        assertEquals(300, decodeBundle(encodeBundle(bundle.copy(contacts = List(300) { io.silencelen.andvari.core.trust.BundleContact(u1, h64, 1) })))!!.contacts.size)
        assertFalse(io.silencelen.andvari.core.trust.DeviceLink.fits(bundle.copy(email = "a".repeat(70_000) + "@b.example")))
        assertNull(decodeBundle("not json"))
        assertNull(decodeBundle("[]"))
    }

    @Test fun outerIsStrict() {
        val o = io.silencelen.andvari.core.trust.DeviceLinkOuter("https://a.example", u1, "a@b.example")
        val enc = io.silencelen.andvari.core.trust.DeviceLink.encodeOuter(o).decodeToString()
        fun decode(t: String) = io.silencelen.andvari.core.trust.DeviceLink.decodeOuter(t.encodeToByteArray())
        assertEquals("""{"v":2,"origin":"https://a.example","userId":"$u1","email":"a@b.example"}""", enc)
        assertEquals(o, decode(enc))
        assertNull(decode(enc.replace("}", ""","more":1}""")))
        assertNull(decode(enc.replace("https://a.example", "http://a.example")))
        assertNull(decode(enc.replace(""""v":2""", """"v":3""")))
        assertNull(decode(enc.replace("a@b.example", " a@b.example")))
        assertNull(decode(enc.replace(""""email"""", """"\u0065mail"""")), "no escape but \\\" and \\\\")
        assertNull(decode(enc.replace(",", ", ")), "no white space outside strings")
        assertNull(decode(enc.replace("}", ""","\u0065mail":"x@y.example"}""")), "an escaped duplicate key")
    }

    @Test fun grammar() {
        val g = WireGrammar
        for (ok in listOf("https://vault.andvaripass.com", "https://a.b", "https://xn--bcher-kva.example:8443", "http://localhost", "http://127.0.0.1:8080", "https://a-b.c0", "http://localhost:443", "https://a.0xg1"))
            assertTrue(g.isOrigin(ok), ok)
        for (no in listOf("https://localhost", "https://example", "https://1.2.3.4", "https://A.example", "https://a.example:443", "https://a.example:0",
            "https://a.example:080", "https://a.example/", "https://a.example.", "https://-a.example", "http://a.example", "http://localhost:0",
            "https://u@a.example", "https://a..example", "ftp://a.example", "https://a.example:65536", "https://[::1]",
            "http://localhost:80", "https://a.0x1f", "https://a.123"))
            assertFalse(g.isOrigin(no), no)
        assertTrue(g.isUuid(u1)); assertFalse(g.isUuid(u1.uppercase())); assertFalse(g.isUuid(u1.replace("-", "")))
        assertTrue(g.isB64_32("A".repeat(42) + "E")); assertFalse(g.isB64_32("A".repeat(42) + "B")); assertFalse(g.isB64_32("A".repeat(44)))
        assertTrue(g.isB64_16("A".repeat(21) + "Q")); assertFalse(g.isB64_16("A".repeat(21) + "B"))
        assertTrue(g.isName("QWxpY2U")); assertFalse(g.isName("")); assertFalse(g.isName("QWxpY2U="))
        assertTrue(g.isHex64n("none")); assertTrue(g.isHex64n(h64)); assertFalse(g.isHex64("A".repeat(64)))
        assertEquals("a@b.example", g.emailNorm(" \tA@B.Example\r\n"))
        assertNull(g.emailNorm("a@b@c")); assertNull(g.emailNorm("@b")); assertNull(g.emailNorm("a@")); assertNull(g.emailNorm("ä@b.example"))
        assertNull(g.emailNorm("a\u0001@b.example")); assertNull(g.emailNorm("a b@c.example")); assertNull(g.emailNorm("a@")); assertNull(g.emailNorm("a@b")); assertEquals("a@b.c", g.emailNorm("a@b.c")); assertNull(g.emailNorm("a".repeat(250) + "@b.ex"))
        assertTrue(g.noDuplicateKeys("""{"a":{"a":1},"b":[{"a":1},{"a":2}],"c":"\"a\""}"""))
        assertFalse(g.noDuplicateKeys("""{"a":1,"b":{"x":1,"x":2}}"""))
        assertFalse(g.noDuplicateKeys("""{"a\"":1,"a\"":2}"""))
        val obj: JsonObject = WireJson.json.parseToJsonElement("""{"n":0,"m":"1","f":1.5,"z":01}""".replace(""","z":01""", "")).jsonObject
        assertEquals(0L, g.intOf(obj["n"])); assertNull(g.intOf(obj["m"])); assertNull(g.intOf(obj["f"]))
    }
}
