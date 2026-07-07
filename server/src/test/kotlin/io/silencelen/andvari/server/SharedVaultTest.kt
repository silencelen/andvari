package io.silencelen.andvari.server

import io.ktor.client.HttpClient
import io.ktor.client.request.delete
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.put
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.AuditEvent
import io.silencelen.andvari.core.model.CreateVaultRequest
import io.silencelen.andvari.core.model.InviteRequest
import io.silencelen.andvari.core.model.InviteResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.UserLookupRequest
import io.silencelen.andvari.core.model.UserLookupResponse
import io.silencelen.andvari.core.model.VaultMemberAdd
import io.silencelen.andvari.core.model.VaultMemberRole
import io.silencelen.andvari.core.model.VaultMemberSummary
import kotlinx.serialization.builtins.ListSerializer
import java.io.File
import java.sql.DriverManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Shared-vault (family sharing, spec 01 §6 / spec 03 §10) server integration, driving the
 * REAL :core sharing crypto through VirtualClient. Exercises the binding fixes: new-member
 * backfill, reader-denied, role change taking effect, removal purge, the vault_mismatch
 * per-mutation `denied` belt, public-origin gating, and the v2→v3 migration.
 */
class SharedVaultTest : P4TestSupport() {

    private suspend fun HttpClient.createVault(vc: VirtualClient, req: CreateVaultRequest): HttpResponse =
        post("/api/v1/vaults") { authed(vc); contentType(ContentType.Application.Json); setBody(req) }

    private suspend fun HttpClient.lookup(vc: VirtualClient, email: String): HttpResponse =
        post("/api/v1/users/lookup") { authed(vc); contentType(ContentType.Application.Json); setBody(UserLookupRequest(email)) }

    private suspend fun HttpClient.addMember(vc: VirtualClient, vaultId: String, add: VaultMemberAdd): HttpResponse =
        post("/api/v1/vaults/$vaultId/members") { authed(vc); contentType(ContentType.Application.Json); setBody(add) }

    private suspend fun HttpClient.members(vc: VirtualClient, vaultId: String): List<VaultMemberSummary> {
        val resp = get("/api/v1/vaults/$vaultId/members") { authed(vc) }
        assertEquals(HttpStatusCode.OK, resp.status, resp.bodyAsText())
        return json.decodeFromString(ListSerializer(VaultMemberSummary.serializer()), resp.bodyAsText())
    }

    private suspend fun HttpClient.setRole(vc: VirtualClient, vaultId: String, userId: String, role: String): HttpResponse =
        put("/api/v1/vaults/$vaultId/members/$userId") { authed(vc); contentType(ContentType.Application.Json); setBody(VaultMemberRole(role)) }

    private suspend fun HttpClient.removeMember(vc: VirtualClient, vaultId: String, userId: String): HttpResponse =
        delete("/api/v1/vaults/$vaultId/members/$userId") { authed(vc) }

    /** Admin invites + enrolls a second, non-admin user against the running server. */
    private suspend fun HttpClient.enrollSecond(admin: VirtualClient, email: String, pw: String): VirtualClient {
        val inv = post("/api/v1/admin/users") {
            authed(admin); contentType(ContentType.Application.Json); setBody(InviteRequest(email, isAdmin = false))
        }
        assertEquals(HttpStatusCode.OK, inv.status, inv.bodyAsText())
        val token = json.decodeFromString(InviteResponse.serializer(), inv.bodyAsText()).inviteToken
        val vc = VirtualClient(email, pw, fast = true)
        register(vc, token)
        return vc
    }

    // ---- 1+2: owner creates a shared vault, adds a writer via lookup→seal→add; the new
    //           member (high cursor) backfills the vault + a pre-existing item and reads it ----

    @Test
    fun sharedVault_createAddWriter_backfillsAndRoundTrips() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "owner sharing password one", fast = true)
        client.register(owner, bootstrapToken)
        val bob = client.enrollSecond(owner, "bob@x.com", "bob sharing password two")

        // Owner creates the shared vault and can re-open its own grant.
        val (createReq, handle) = owner.buildCreateSharedVault()
        assertEquals(HttpStatusCode.Created, client.createVault(owner, createReq).status)
        val ownerSync = client.sync(owner)
        val ownerGrant = ownerSync.grants.single { it.vaultId == handle.vaultId }
        assertEquals("owner", ownerGrant.role)
        val ownerVk = owner.openOwnGrant(handle.vaultId, ownerGrant.wrappedVk)
        assertTrue(ownerVk.contentEquals(handle.vk))

        // Owner puts a PRE-EXISTING item into the shared vault BEFORE bob is added.
        val sharedItem = owner.newItemId()
        client.push(owner, Mutation(uuid(), "put", sharedItem, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, sharedItem, """{"name":"wifi"}""")))

        // Bob advances his cursor to "now" (so the vault/item revs are already in his past).
        val bobCursor = client.sync(bob).rev

        // Owner looks bob up, seals the VK to bob's identity pub, adds him as writer.
        val lr = client.lookup(owner, "bob@x.com")
        assertEquals(HttpStatusCode.OK, lr.status, lr.bodyAsText())
        val bobInfo = json.decodeFromString(UserLookupResponse.serializer(), lr.bodyAsText())
        assertEquals(bob.userId, bobInfo.userId)
        val sealed = owner.sealVkFor(io.silencelen.andvari.core.crypto.Bytes.fromB64(bobInfo.identityPub), handle.vaultId, handle.vk)
        assertEquals(HttpStatusCode.Created, client.addMember(owner, handle.vaultId, VaultMemberAdd(bob.userId, "writer", sealed)).status)

        // Backfill: bob pulls from his ALREADY-ADVANCED cursor and STILL gets the vault + grant + the
        // pre-existing item (defect #0.2 regression). He opens the sealed grant and decrypts.
        val bobSync = client.sync(bob, bobCursor)
        val bobGrant = bobSync.grants.single { it.vaultId == handle.vaultId }
        assertEquals("writer", bobGrant.role)
        assertTrue(bobGrant.wrappedVk.isEmpty() && bobGrant.sealedVk != null, "member grant carries sealedVk, not wrappedVk")
        val bobVk = bob.openSharedGrant(handle.vaultId, bobGrant.sealedVk!!)
        assertTrue(bobVk.contentEquals(handle.vk))
        val backfilled = bobSync.items.single { it.itemId == sharedItem }
        assertEquals("""{"name":"wifi"}""", bob.decItemIn(handle.vaultId, bobVk, sharedItem, backfilled.blob!!))

        // Writer bob writes; owner sees it.
        val bobItem = bob.newItemId()
        client.push(bob, Mutation(uuid(), "put", bobItem, handle.vaultId, 0, bob.encItemIn(handle.vaultId, bobVk, bobItem, """{"name":"from-bob"}""")))
        val ownerItem = client.sync(owner, ownerSync.rev).items.single { it.itemId == bobItem }
        assertEquals("""{"name":"from-bob"}""", owner.decItemIn(handle.vaultId, ownerVk, bobItem, ownerItem.blob!!))

        // Members list shows both, active only.
        assertEquals(setOf(owner.userId, bob.userId), client.members(owner, handle.vaultId).map { it.userId }.toSet())
    }

    // ---- 3: a reader can pull/decrypt but push → denied (+audit) and attachment POST → 403 ----

    @Test
    fun sharedVault_reader_cannotWrite() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner2@x.com", "owner reader password one", fast = true)
        client.register(owner, bootstrapToken)
        val carol = client.enrollSecond(owner, "carol@x.com", "carol reader password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val ci = json.decodeFromString(UserLookupResponse.serializer(), client.lookup(owner, "carol@x.com").bodyAsText())
        val sealed = owner.sealVkFor(io.silencelen.andvari.core.crypto.Bytes.fromB64(ci.identityPub), handle.vaultId, handle.vk)
        client.addMember(owner, handle.vaultId, VaultMemberAdd(carol.userId, "reader", sealed))

        val carolVk = carol.openSharedGrant(handle.vaultId, client.sync(carol).grants.single { it.vaultId == handle.vaultId }.sealedVk!!)

        // Reader push → per-item denied + a push_denied audit row.
        val itemId = carol.newItemId()
        val denied = client.push(carol, Mutation(uuid(), "put", itemId, handle.vaultId, 0, carol.encItemIn(handle.vaultId, carolVk, itemId, """{"name":"nope"}""")))
        assertEquals("denied", denied.results[0].status)
        assertTrue(client.auditRows(owner, "push_denied").any { it.userId == carol.userId })

        // Reader attachment upload → 403.
        val att = client.uploadAttachment(carol, uuid(), itemId, ByteArray(64) { 1 }, handle.vaultId)
        assertEquals(HttpStatusCode.Forbidden, att.status)
    }

    // ---- 4: role change reader→writer takes effect (grant rev bump re-delivers) ----

    @Test
    fun sharedVault_roleChange_reDeliversGrant() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner3@x.com", "owner role password one", fast = true)
        client.register(owner, bootstrapToken)
        val dave = client.enrollSecond(owner, "dave@x.com", "dave role password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val di = json.decodeFromString(UserLookupResponse.serializer(), client.lookup(owner, "dave@x.com").bodyAsText())
        val sealed = owner.sealVkFor(io.silencelen.andvari.core.crypto.Bytes.fromB64(di.identityPub), handle.vaultId, handle.vk)
        client.addMember(owner, handle.vaultId, VaultMemberAdd(dave.userId, "reader", sealed))
        val cursor = client.sync(dave).rev // dave now holds reader

        // Promote to writer; the grant rev bumps so a pull from dave's cursor re-delivers it.
        assertEquals(HttpStatusCode.OK, client.setRole(owner, handle.vaultId, dave.userId, "writer").status)
        val reDelivered = client.sync(dave, cursor).grants.single { it.vaultId == handle.vaultId }
        assertEquals("writer", reDelivered.role)
    }

    // ---- 5: remove member → victim's pull carries removedGrants; access stops; others unaffected ----

    @Test
    fun sharedVault_removeMember_revokesAccess() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner4@x.com", "owner remove password one", fast = true)
        client.register(owner, bootstrapToken)
        val erin = client.enrollSecond(owner, "erin@x.com", "erin remove password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val ei = json.decodeFromString(UserLookupResponse.serializer(), client.lookup(owner, "erin@x.com").bodyAsText())
        val sealed = owner.sealVkFor(io.silencelen.andvari.core.crypto.Bytes.fromB64(ei.identityPub), handle.vaultId, handle.vk)
        client.addMember(owner, handle.vaultId, VaultMemberAdd(erin.userId, "writer", sealed))
        val erinVk = erin.openSharedGrant(handle.vaultId, client.sync(erin).grants.single { it.vaultId == handle.vaultId }.sealedVk!!)
        val cursor = client.sync(erin).rev

        assertEquals(HttpStatusCode.OK, client.removeMember(owner, handle.vaultId, erin.userId).status)

        // Victim's next pull: removedGrants names the vault; no items of it delivered.
        val after = client.sync(erin, cursor)
        assertTrue(after.removedGrants.contains(handle.vaultId))
        assertTrue(after.items.none { it.vaultId == handle.vaultId })

        // Erin's writes are now denied.
        val itemId = erin.newItemId()
        val denied = client.push(erin, Mutation(uuid(), "put", itemId, handle.vaultId, 0, erin.encItemIn(handle.vaultId, erinVk, itemId, """{"name":"after"}""")))
        assertEquals("denied", denied.results[0].status)

        // Owner is unaffected; members list no longer includes erin.
        assertEquals(setOf(owner.userId), client.members(owner, handle.vaultId).map { it.userId }.toSet())
    }

    // ---- 6: authorization + validation — non-owner, self-target, bad role, duplicate, lookup 404 ----

    @Test
    fun sharedVault_authAndValidation() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner5@x.com", "owner auth password one", fast = true)
        client.register(owner, bootstrapToken)
        val frank = client.enrollSecond(owner, "frank@x.com", "frank auth password two")

        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val fi = json.decodeFromString(UserLookupResponse.serializer(), client.lookup(owner, "frank@x.com").bodyAsText())
        val sealedF = owner.sealVkFor(io.silencelen.andvari.core.crypto.Bytes.fromB64(fi.identityPub), handle.vaultId, handle.vk)

        // Non-owner (frank, not yet a member) cannot add members.
        assertEquals(HttpStatusCode.Forbidden, client.addMember(frank, handle.vaultId, VaultMemberAdd(owner.userId, "reader", sealedF)).status)
        // Owner cannot target self.
        assertEquals(HttpStatusCode.BadRequest, client.addMember(owner, handle.vaultId, VaultMemberAdd(owner.userId, "reader", sealedF)).status)
        // Bad role rejected.
        assertEquals(HttpStatusCode.BadRequest, client.addMember(owner, handle.vaultId, VaultMemberAdd(frank.userId, "admin", sealedF)).status)
        // Valid add, then duplicate → already_member.
        assertEquals(HttpStatusCode.Created, client.addMember(owner, handle.vaultId, VaultMemberAdd(frank.userId, "reader", sealedF)).status)
        assertEquals(HttpStatusCode.BadRequest, client.addMember(owner, handle.vaultId, VaultMemberAdd(frank.userId, "reader", sealedF)).status)
        // Lookup of an unknown email → 404 + audit row. Raw target emails must never land
        // in audit meta (INFO-1 data minimization — audit rows ship to the central log store).
        assertEquals(HttpStatusCode.NotFound, client.lookup(owner, "ghost@x.com").status)
        val lookups = client.auditRows(owner, "user_lookup")
        assertTrue(lookups.isNotEmpty())
        assertTrue(lookups.none { it.meta?.contains("@") == true })
    }

    // ---- 7: vault_mismatch — a put targeting an existing item under the WRONG vaultId is a
    //          per-mutation `denied` (NOT a thrown 400 that would wedge old clients) ----

    @Test
    fun vaultMismatch_isPerMutationDenied_notThrown() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner6@x.com", "owner mismatch password one", fast = true)
        client.register(owner, bootstrapToken)

        // Create an item in the personal vault.
        val itemId = owner.newItemId()
        client.push(owner, putMutation(owner, itemId, """{"name":"home"}""", 0))

        // Create a shared vault, then push a put for the SAME itemId but claiming the shared vaultId.
        val (createReq, handle) = owner.buildCreateSharedVault()
        client.createVault(owner, createReq)
        val bad = Mutation(uuid(), "put", itemId, handle.vaultId, 0, owner.encItemIn(handle.vaultId, handle.vk, itemId, """{"name":"moved"}"""))
        val resp = client.push(owner, bad) // 200 overall, per-item denied — the batch is NOT rejected
        assertEquals("denied", resp.results[0].status)
        assertTrue(client.auditRows(owner, "push_denied").any { it.meta?.startsWith("vault_mismatch:") == true })

        // The item stayed in the personal vault, unmoved.
        assertEquals(owner.personalVaultId, client.sync(owner).items.single { it.itemId == itemId }.vaultId)
    }

    // ---- 8: shared-vault + lookup routes refused on the public break-glass origin ----

    @Test
    fun sharedVault_refusedOnPublicOrigin() = testApplication {
        application { andvariModule(buildServices(config(publicHostname = "andvari.example.com"), Notifier())) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner7@x.com", "owner public password one", fast = true)
        client.register(owner, bootstrapToken)
        val (createReq, _) = owner.buildCreateSharedVault()

        val resp = client.post("/api/v1/vaults") {
            authed(owner); header("Host", "andvari.example.com"); contentType(ContentType.Application.Json); setBody(createReq)
        }
        assertEquals(HttpStatusCode.Forbidden, resp.status)
        assertEquals("sharing_public_disabled", errorOf(resp))
    }

    // ---- v2 → v3 migration on a live-shaped DB: ALTER adds sealedVk (null on old rows), idempotent ----

    @Test
    fun migration_v2ToV3_addsNullableSealedVk() {
        val dbFile = File(tmpDir, "v2fixture-${System.nanoTime()}.db")
        // Hand-build a v2-shaped DB: meta(schemaVersion=2) + the v1 grants table (no sealedVk).
        DriverManager.getConnection("jdbc:sqlite:${dbFile.absolutePath}").use { c ->
            c.createStatement().use { st ->
                st.executeUpdate("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                st.executeUpdate(
                    """CREATE TABLE grants(vaultId TEXT NOT NULL, userId TEXT NOT NULL, role TEXT NOT NULL,
                       wrappedVk TEXT NOT NULL, rev INTEGER NOT NULL, revokedAt INTEGER, PRIMARY KEY(vaultId,userId))""",
                )
                st.executeUpdate("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev) VALUES('v','u','owner','wv',1)")
                st.executeUpdate("INSERT INTO meta(key,value) VALUES('schemaVersion','2')")
            }
        }

        // Opening through Db() runs the v3 migration on the live-shaped DB.
        Db(dbFile.absolutePath).use { db ->
            val (version, sealed) = db.read { c ->
                val v = c.queryOne("SELECT value FROM meta WHERE key='schemaVersion'") { it.getString(1) }
                val s = c.queryOne("SELECT sealedVk FROM grants WHERE userId='u'") { rs -> rs.getString(1) }
                v to s
            }
            assertEquals("3", version)
            assertNull(sealed, "the pre-existing v2 grant reads back sealedVk=NULL")
        }
        // Re-opening is idempotent (already v3 — the ALTER does not re-run).
        Db(dbFile.absolutePath).use { db ->
            assertEquals("3", db.read { c -> c.queryOne("SELECT value FROM meta WHERE key='schemaVersion'") { it.getString(1) } })
        }
    }
}
