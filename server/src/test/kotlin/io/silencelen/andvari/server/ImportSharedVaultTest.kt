package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.CsvImport
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.LoginData
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * S2 (destination-vault import): the shared-vault round trip the native pickers rely on,
 * end-to-end against the real server. ONE vaultId feeds importProjections (the F75 plan)
 * AND importAll (the commit) — a mismatch would fingerprint the dedupe against one vault
 * while the rows land in another. Pinned here: projections see ONLY the destination
 * vault (per-vault, not per-account), planned rows land IN it, and replaying the SAME
 * plan is idempotent (mutationId = itemId, so a retry converges instead of duplicating).
 */
class ImportSharedVaultTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "import-shared-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-import-shared").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "imp-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 9 }, publicHostname = null, bootstrapToken = bootstrap,
    )

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    private suspend fun enroll(api: AndvariApi, email: String, password: String): Account {
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            bootstrap, email, email.substringBefore('@'), password,
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "device", crypto,
        )
        api.register(req)
        return account
    }

    @Test
    fun sharedVaultImport_landsInDestination_andReplaysIdempotently() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }

        val api = AndvariApi("", createClient { })
        val owner = enroll(api, "imp@fam.com", "import shared password one")
        val engine = SyncEngine(api, owner, InMemoryVaultCache())
        engine.sync()

        // A shared vault + one pre-existing login in EACH vault: proving the projections
        // are per-vault needs both sides populated.
        val nv = owner.buildCreateSharedVault("Family")
        api.createVault(nv.request)
        engine.sync()
        engine.save(null, ItemDoc(type = "login", name = "shared-wifi", login = LoginData(username = "u", password = "p", uris = listOf("https://wifi.example"))), vaultId = nv.vaultId)
        engine.save(null, ItemDoc(type = "login", name = "personal-mail", login = LoginData(username = "me", password = "pw", uris = listOf("https://mail.example"))))

        // S2 invariant: ONE variable feeds the plan's projections AND the commit below.
        val dest = nv.vaultId
        val proj = engine.importProjections(dest)
        assertEquals(listOf("shared-wifi"), proj.names, "projections see ONLY the destination vault")

        // Chrome-shaped CSV: one fresh row + one row identical to the SHARED vault's own
        // item — the F75 dedupe must resolve it against the destination, not personal.
        val csv = """
            name,url,username,password
            gmail,https://mail.google.com,me@x.com,pw1
            shared-wifi,https://wifi.example,u,p
        """.trimIndent().encodeToByteArray()
        val plan = CsvImport.plan(CsvImport.parse(csv), proj) { owner.newItemId() }
        assertEquals(listOf("shared-wifi"), plan.report.alreadyInVault, "the destination's own item deduped (rule 1)")
        assertEquals(1, plan.report.imported)

        engine.importAll(plan.items, vaultId = dest)
        val imported = engine.items().single { it.doc.name == "gmail" }
        assertEquals(dest, imported.vaultId, "the imported row landed IN the destination vault")
        val before = engine.items().map { it.itemId to it.vaultId }.toSet()

        // Idempotent replay of the SAME plan (the Retry path): server key deviceId+mutationId
        // converges — same ids, same vaults, no duplicates.
        engine.importAll(plan.items, vaultId = dest)
        assertEquals(before, engine.items().map { it.itemId to it.vaultId }.toSet(), "re-import kept the same ids and created no duplicates")
    }
}
