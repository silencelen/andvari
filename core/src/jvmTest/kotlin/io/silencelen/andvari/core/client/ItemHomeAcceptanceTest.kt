package io.silencelen.andvari.core.client

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.AccountStateResponse
import io.silencelen.andvari.core.model.Mutation
import io.silencelen.andvari.core.model.MutationResult
import io.silencelen.andvari.core.model.PushRequest
import io.silencelen.andvari.core.model.PushResponse
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.SyncResponse
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import io.silencelen.andvari.core.model.WireVault
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Item home (security review 2026-10, root cause A §5; branch A1b). The campaign HIGH A-4 and its core twin: a hostile
 * server serves a conflict-flagged row for an item this device holds in vault P under ANOTHER vault S (a vault whose
 * key the server or a colluding co-member holds), next to the genuine row. Before A1b the client re-sealed P's
 * plaintext under S's key and pushed it. These are the §5.3 acceptance cases, on the path a real client takes, for
 * both row orders and for a warm and a cold (hydrated) client:
 *  1. no push carries an envelope under S whose plaintext is P's doc for X (every pushed S envelope is decrypted);
 *  2. `item(X).vaultId == P` and P's doc is unchanged;
 *  3. exactly one "the server sent an item under the wrong vault" anomaly;
 *  4. in-window, a v1-only S is legacy-read-only and INV-WRITE-KEY blocks any seal under it on its own.
 * Plus INV-HOME for a served tombstone and across a resync, and INV-EDIT on the editor save. Web twin:
 * `web/src/vault/store.itemhome.test.ts`.
 */
class ItemHomeAcceptanceTest {
    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192)
    private val password = "correct horse battery staple"
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt, kdfParams = reg.kdfParams, wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed, identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint, personalWrap = reg.personalWrap,
            ),
        )
    }

    private fun device(e: Enrolled) = Account.unlock(e.reg.userId, password, e.keys, crypto)

    /** A scripted hostile server: a queue of sync responses, and every mutation the client pushes. */
    private inner class Server {
        val queue = ArrayDeque<SyncResponse>()
        val pushed = mutableListOf<Mutation>()
        var rev = 100L
        /** Answer the next delta pull with 410, forcing a since=0 resync (served from [queue]). */
        var resyncOnce = false
        /** When set, a put for this itemId is answered `conflict` with this row as the displaced (losing) value. */
        var conflictFor: Pair<String, WireItem>? = null

        fun api(): AndvariApi {
            val engine = MockEngine { req ->
                val path = req.url.encodedPath
                val ct = headersOf(HttpHeaders.ContentType, "application/json")
                fun ok(body: String) = respond(body, HttpStatusCode.OK, ct)
                when {
                    path == "/api/v1/sync" && resyncOnce && req.url.parameters["since"] != "0" -> {
                        resyncOnce = false
                        respond("""{"error":"resync_required","message":"gone"}""", HttpStatusCode.Gone, ct)
                    }
                    path == "/api/v1/sync" -> {
                        val resp = queue.removeFirstOrNull() ?: SyncResponse(rev, false, emptyList(), emptyList(), emptyList(), emptyList())
                        ok(json.encodeToString(SyncResponse.serializer(), resp))
                    }
                    path == "/api/v1/sync/push" -> {
                        val body = json.decodeFromString(PushRequest.serializer(), req.body.toByteArray().decodeToString())
                        pushed += body.mutations
                        val results = body.mutations.map {
                            val c = conflictFor
                            if (c != null && it.itemId == c.first && it.op == "put") MutationResult(it.mutationId, "conflict", newItemRev = ++rev, serverItem = c.second)
                            else MutationResult(it.mutationId, "applied", newItemRev = ++rev)
                        }
                        ok(json.encodeToString(PushResponse.serializer(), PushResponse(rev, results)))
                    }
                    path == "/api/v1/account/state" && req.method == HttpMethod.Get ->
                        ok(json.encodeToString(AccountStateResponse.serializer(), AccountStateResponse(null, 0)))
                    else -> respond("""{"error":"not_found","message":"unexpected $path"}""", HttpStatusCode.NotFound, ct)
                }
            }
            return AndvariApi("http://fake", HttpClient(engine), Tokens("access", "refresh"))
        }
    }

    /**
     * The §5.3 fixture. P = the victim's personal vault, holding X. S = a second vault: [writable] = false is the
     * review's exploit (a v1 grant sealed to the victim around a key the test holds, legacy-read-only in-window);
     * [writable] = true is S as a vault the victim owns and a colluding co-member can read (INV-HOME has to hold on
     * its own there, with no INV-WRITE-KEY behind it).
     */
    private inner class World(val writable: Boolean) {
        val victim = enroll("victim-${crypto.randomBytes(4).joinToString("") { (it.toInt() and 0xff).toString(16) }}@example.com")
        val p = victim.reg.personalVault.vaultId
        val x = victim.account.newItemId()
        val docP = ItemDoc(type = "login", name = "Bank", login = LoginData(username = "me", password = "P-SECRET-0001"))
        val bait = ItemDoc(type = "login", name = "Bank", login = LoginData(username = "me", password = "server-chosen"))
        private val shared = if (writable) victim.account.buildCreateSharedVault("Household") else null
        val s: String = shared?.vaultId ?: victim.account.newItemId()
        val vkS: ByteArray = crypto.randomBytes(32)

        val personalRow = WireVault(p, "personal", 2, victim.reg.personalVault.metaBlob, 0)
        val personalGrant = WireGrant(p, victim.reg.userId, "owner", victim.reg.personalVault.wrappedVk, 2, null)
        val sRow: WireVault = if (shared != null) WireVault(s, "shared", 7, shared.request.metaBlob, 0)
        else WireVault(s, "shared", 7, Envelope.sealB64(crypto, vkS, """{"name":"Server"}""".encodeToByteArray(), Ad.vaultMeta(s)), 0)
        val sGrant: WireGrant = if (shared != null) WireGrant(s, victim.reg.userId, "owner", shared.request.wrappedVk, 7, null)
        else WireGrant(s, victim.reg.userId, "writer", "", 7, Bytes.toB64(SharedGrant.seal(crypto, victim.account.identityPub, s, vkS)))

        private fun sealS(itemId: String, doc: ItemDoc): String =
            if (writable) victim.account.encryptItem(s, itemId, doc).blob
            else Envelope.sealB64(crypto, vkS, json.encodeToString(ItemDoc.serializer(), doc).encodeToByteArray(), Ad.item(s, itemId, 1))

        val genuine: WireItem = victim.account.encryptItem(p, x, docP).let {
            WireItem(x, p, 3, 1, 1, false, false, it.formatVersion, it.attachmentIds, it.blob)
        }
        val flagged = WireItem(x, s, 8, 1, 2, false, true, 1, emptyList(), sealS(x, bait))

        /** Decrypt an S envelope the client pushed; null when it does not open under S's key. */
        fun openS(m: Mutation): ItemDoc? {
            val up = m.item ?: return null
            return runCatching {
                if (writable) victim.account.decryptItem(WireItem(m.itemId, s, 1, 1, 1, false, false, up.formatVersion, up.attachmentIds, up.blob))
                else json.decodeFromString(ItemDoc.serializer(), Envelope.openB64(crypto, vkS, up.blob, Ad.item(s, m.itemId, up.formatVersion)).decodeToString())
            }.getOrNull()
        }

        fun seedFeed() = SyncResponse(5, true, listOf(personalRow), listOf(personalGrant), listOf(genuine), emptyList())

        /** One /sync response: the S grant + vault, the flagged S row and the genuine P row, in either order. */
        fun fixture(flaggedFirst: Boolean, rev: Long = 9) = SyncResponse(
            rev, false, listOf(sRow), listOf(sGrant),
            if (flaggedFirst) listOf(flagged, genuine.copy(rev = 6)) else listOf(genuine.copy(rev = 6), flagged),
            emptyList(),
        )
    }

    /** Build a warm (one engine all along) or cold (a fresh Account + engine hydrated from the same cache) client. */
    private fun client(w: World, server: Server, cold: Boolean): Pair<Account, SyncEngine> = runBlocking {
        val cache = InMemoryVaultCache()
        val first = device(w.victim)
        val e1 = SyncEngine(server.api(), first, cache)
        server.queue.add(w.seedFeed())
        e1.sync()
        assertEquals(w.p, e1.item(w.x)?.vaultId, "precondition: X lives in P")
        if (!cold) return@runBlocking first to e1
        val second = device(w.victim)
        val e2 = SyncEngine(server.api(), second, cache)
        e2.hydrate()
        second to e2
    }

    private fun assertAcceptance(w: World, server: Server, acct: Account, engine: SyncEngine, label: String) {
        // 1. No push carries an S envelope whose plaintext is P's doc for X (decrypt every one and compare).
        for (m in server.pushed.filter { it.vaultId == w.s }) {
            val doc = w.openS(m)
            assertTrue(doc == null || doc.login?.password != w.docP.login?.password, "$label: P's plaintext was sealed under S and pushed: $doc")
        }
        // 2. X stays in P, and P's doc is unchanged.
        val x = engine.item(w.x)
        assertEquals(w.p, x?.vaultId, "$label: a served row moved X out of P")
        assertEquals(w.docP, x?.doc, "$label: P's doc changed")
        assertEquals(1, engine.items().count { it.itemId == w.x }, "$label: exactly one live X")
        // 3. Exactly one wrong-vault anomaly.
        assertEquals(1, engine.notices().count { it.kind == "wrong-vault" }, "$label: one 'wrong vault' anomaly: ${engine.notices().map { it.kind }}")
        // 4. In-window a v1-only S is legacy-read-only, and INV-WRITE-KEY refuses any seal under it on its own.
        if (!w.writable) {
            assertTrue(acct.isLegacyReadOnly(w.s), "$label: a v1-only S is legacy-read-only")
            assertFailsWith<VaultKeyNotVerifiedException> { acct.encryptItem(w.s, acct.newItemId(), w.docP) }
        }
    }

    private fun acceptance(writable: Boolean, flaggedFirst: Boolean, cold: Boolean) = runBlocking {
        val w = World(writable)
        val server = Server()
        val (acct, engine) = client(w, server, cold)
        server.queue.add(w.fixture(flaggedFirst))
        engine.sync()
        assertAcceptance(w, server, acct, engine, "writable=$writable flaggedFirst=$flaggedFirst cold=$cold")
    }

    @Test fun acceptance_v1S_flaggedFirst_warm() = acceptance(writable = false, flaggedFirst = true, cold = false)
    @Test fun acceptance_v1S_genuineFirst_warm() = acceptance(writable = false, flaggedFirst = false, cold = false)
    @Test fun acceptance_v1S_flaggedFirst_cold() = acceptance(writable = false, flaggedFirst = true, cold = true)
    @Test fun acceptance_v1S_genuineFirst_cold() = acceptance(writable = false, flaggedFirst = false, cold = true)
    @Test fun acceptance_writableS_flaggedFirst_warm() = acceptance(writable = true, flaggedFirst = true, cold = false)
    @Test fun acceptance_writableS_genuineFirst_warm() = acceptance(writable = true, flaggedFirst = false, cold = false)
    @Test fun acceptance_writableS_flaggedFirst_cold() = acceptance(writable = true, flaggedFirst = true, cold = true)
    @Test fun acceptance_writableS_genuineFirst_cold() = acceptance(writable = true, flaggedFirst = false, cold = true)

    /** The core MEDIUM (API review #3): after the fixture, the editor's save of X must seal under P, never S. */
    @Test
    fun theEditorSaveAfterTheFixtureSealsUnderP() = runBlocking {
        val w = World(writable = true)
        val server = Server()
        val (_, engine) = client(w, server, cold = false)
        server.queue.add(w.fixture(flaggedFirst = false))
        engine.sync()
        server.pushed.clear()
        val edited = w.docP.copy(login = w.docP.login!!.copy(password = "P-SECRET-0002"))
        engine.save(w.x, edited, w.p) // the editor opened X in P
        val puts = server.pushed.filter { it.itemId == w.x && it.op == "put" }
        assertEquals(listOf(w.p), puts.map { it.vaultId }, "the edit is sealed under the editor's vault, P")
        for (m in server.pushed.filter { it.vaultId == w.s }) assertTrue(w.openS(m)?.login?.password?.startsWith("P-SECRET") != true)
    }

    /** INV-EDIT: an editor bound to another vault than X's home is refused, and nothing is re-targeted. */
    @Test
    fun aSaveFromAnEditorBoundToAnotherVaultIsRefused() = runBlocking {
        val w = World(writable = true)
        val server = Server()
        val (_, engine) = client(w, server, cold = false)
        server.queue.add(SyncResponse(9, false, listOf(w.sRow), listOf(w.sGrant), emptyList(), emptyList()))
        engine.sync()
        server.pushed.clear()
        val e = assertFailsWith<Exception> { engine.save(w.x, w.docP.copy(name = "Bank 2"), w.s) }
        assertTrue(e.message?.contains("changed vaults", ignoreCase = true) == true, "the refusal names the cause: ${e.message}")
        assertTrue(server.pushed.none { it.itemId == w.x }, "nothing pushed: ${server.pushed}")
    }

    /** INV-HOME covers tombstones: a served delete of X under S does not delete X from P. */
    @Test
    fun aTombstoneUnderTheWrongVaultIsNotApplied() = runBlocking {
        val w = World(writable = true)
        val server = Server()
        val (_, engine) = client(w, server, cold = false)
        val tomb = WireItem(w.x, w.s, 8, 1, 3, true, false, 1, emptyList(), null)
        server.queue.add(SyncResponse(9, false, listOf(w.sRow), listOf(w.sGrant), listOf(tomb), emptyList()))
        engine.sync()
        assertEquals(w.p, engine.item(w.x)?.vaultId, "X is still in P")
        assertEquals(1, engine.notices().count { it.kind == "wrong-vault" })
    }

    /** The home survives a 410 resync-from-0 (a server-triggered wipe of the row stores): a full snapshot that serves
     *  X only under S does not re-home it. */
    @Test
    fun theHomeSurvivesAResync() = runBlocking {
        val w = World(writable = true)
        val server = Server()
        val (_, engine) = client(w, server, cold = true)
        server.resyncOnce = true
        server.queue.add(SyncResponse(9, true, listOf(w.personalRow, w.sRow), listOf(w.personalGrant, w.sGrant), listOf(w.flagged.copy(conflict = false)), emptyList()))
        engine.sync()
        assertTrue(engine.items().none { it.itemId == w.x && it.vaultId == w.s }, "X was not re-homed into S")
        assertTrue(engine.envelopes().none { it.itemId == w.x && it.vaultId == w.s }, "the S row is quarantined, not cached as X")
        assertEquals(1, engine.notices().count { it.kind == "wrong-vault" })
    }

    /** INV-CONFLICT, push side: a server answering our P write with a "displaced value" under S gets no copy in S. */
    @Test
    fun aDisplacedValueUnderAnotherVaultIsNotCopied() = runBlocking<Unit> {
        val w = World(writable = true)
        val server = Server()
        val (_, engine) = client(w, server, cold = false)
        server.queue.add(SyncResponse(9, false, listOf(w.sRow), listOf(w.sGrant), emptyList(), emptyList()))
        engine.sync()
        server.pushed.clear()
        server.conflictFor = w.x to w.flagged.copy(conflict = false)
        engine.save(w.x, w.docP.copy(name = "Bank (edited)"), w.p)
        assertTrue(server.pushed.none { it.vaultId == w.s }, "no copy sealed under S: ${server.pushed.map { it.vaultId }}")
        assertEquals(1, engine.notices().count { it.kind == "wrong-vault" })
        assertEquals(w.p, engine.item(w.x)?.vaultId)
    }

    /** INV-WRITE-KEY on every core path (save, copy-into, import, restore): a v1-only S is never written under. */
    @Test
    fun noPathSealsUnderALegacyReadOnlyKey() = runBlocking<Unit> {
        val w = World(writable = false)
        val server = Server()
        val (acct, engine) = client(w, server, cold = false)
        server.queue.add(SyncResponse(9, false, listOf(w.sRow), listOf(w.sGrant), emptyList(), emptyList()))
        engine.sync()
        assertTrue(acct.isLegacyReadOnly(w.s))
        server.pushed.clear()
        assertFailsWith<VaultKeyNotVerifiedException> { engine.save(null, w.docP.copy(name = "new in S"), w.s) }
        val g = engine.newMoveGesture(w.x, w.s, del = false)
        assertFailsWith<VaultKeyNotVerifiedException> { engine.runGesture(g) }
        assertFailsWith<VaultKeyNotVerifiedException> { engine.importAll(listOf(CsvImport.PlannedItem(acct.newItemId(), w.docP)), vaultId = w.s) }
        assertFailsWith<VaultKeyNotVerifiedException> { engine.restoreDeleted(acct.newItemId(), w.s, w.docP) }
        assertTrue(server.pushed.none { it.vaultId == w.s }, "nothing was pushed under S")
    }

    /** INV-SEAL: a restore or a move can never seal an item under another vault than its home. */
    @Test
    fun aRestoreUnderAnotherVaultThanTheHomeIsRefused() = runBlocking<Unit> {
        val w = World(writable = true)
        val server = Server()
        val (_, engine) = client(w, server, cold = false)
        server.queue.add(SyncResponse(9, false, listOf(w.sRow), listOf(w.sGrant), emptyList(), emptyList()))
        engine.sync()
        assertFailsWith<ItemChangedVaultsException> { engine.restoreDeleted(w.x, w.s, w.docP) }
        val g = engine.newMoveGesture(w.x, w.s, del = true)
        assertTrue(g.newItemId != w.x, "move/copy mint a fresh id")
        assertFailsWith<ItemChangedVaultsException> { engine.runGesture(g.copy(sourceVaultId = w.s)) }
    }
}
