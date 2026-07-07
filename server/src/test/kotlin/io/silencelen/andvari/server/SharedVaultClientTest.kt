package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.InMemoryVaultCache
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.SyncEngine
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.VaultMemberAdd
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Family sharing driven end-to-end through the REAL :core client (Account.addGrant with
 * sealed grants, roleFor, save-into-shared-vault, removedGrants purge) — the Kotlin
 * counterpart of the web sharing flow, against an in-process server on schema v3.
 */
class SharedVaultClientTest {
    private val crypto = createCryptoProvider()
    private val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
    private val fingerprint = Escrow.fingerprint(crypto, recovery.publicKey)
    private val bootstrap = "shared-client-bootstrap"
    private val tmp = Files.createTempDirectory("andvari-shared-client").toFile()

    private fun config() = Config(
        host = "127.0.0.1", port = 0,
        dbPath = File(tmp, "s-${System.nanoTime()}.db").absolutePath,
        blobDir = File(tmp, "blobs").absolutePath, webDir = null,
        recoveryPublicKey = recovery.publicKey, recoveryFingerprint = fingerprint,
        enumSecret = ByteArray(32) { 9 }, publicHostname = null, bootstrapToken = bootstrap,
    )

    @AfterTest fun cleanup() { tmp.deleteRecursively() }

    private suspend fun enroll(api: AndvariApi, email: String, password: String, invite: String): Account {
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val (req, account) = Account.enroll(
            invite, email, email.substringBefore('@'), password,
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "device", crypto,
        )
        api.register(req)
        return account
    }

    @Test
    fun familySharing_endToEnd_throughCore() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }

        // Owner (admin via bootstrap) + a second family member (invited).
        val apiOwner = AndvariApi("", createClient { })
        val owner = enroll(apiOwner, "own@fam.com", "owner family password one", bootstrap)
        val engineOwner = SyncEngine(apiOwner, owner, InMemoryVaultCache())
        engineOwner.sync()

        val memberInvite = services.admin.createInvite("kid@fam.com", isAdmin = false, byUserId = owner.userId).second
        val apiMember = AndvariApi("", createClient { })
        val member = enroll(apiMember, "kid@fam.com", "member family password two", memberInvite)
        val engineMember = SyncEngine(apiMember, member, InMemoryVaultCache())
        engineMember.sync()

        // Owner creates the shared vault and puts an item in it BEFORE the member joins.
        val nv = owner.buildCreateSharedVault("Family")
        apiOwner.createVault(nv.request)
        engineOwner.sync()
        engineOwner.save(null, ItemDoc(type = "login", name = "wifi"), vaultId = nv.vaultId)

        // Lookup + out-of-band fingerprint check + seal + add as WRITER.
        val info = apiOwner.lookupUser("kid@fam.com")
        assertEquals(member.identityFingerprintShort(), io.silencelen.andvari.core.crypto.SharedGrant.shortFingerprint(crypto, Bytes.fromB64(info.identityPub)),
            "the fingerprint the owner verifies matches what the member's own client displays")
        val sealed = owner.wrapVkForMember(Bytes.fromB64(info.identityPub), nv.vaultId)
        apiOwner.addVaultMember(nv.vaultId, VaultMemberAdd(member.userId, "writer", sealed))

        // Member syncs: sealed grant opens, backfilled item decrypts, role is writer.
        engineMember.sync()
        assertEquals("writer", member.roleFor(nv.vaultId))
        assertTrue(engineMember.items().any { it.doc.name == "wifi" && it.vaultId == nv.vaultId })

        // Member writes into the shared vault; owner sees it. Owner EDITS the member's
        // item — the edit stays in the shared vault (never re-homed to personal).
        engineMember.save(null, ItemDoc(type = "note", name = "from-kid"), vaultId = nv.vaultId)
        engineOwner.sync()
        val fromKid = engineOwner.items().single { it.doc.name == "from-kid" }
        assertEquals(nv.vaultId, fromKid.vaultId)
        engineOwner.save(fromKid.itemId, fromKid.doc.copy(name = "from-kid-edited"))
        engineMember.sync()
        val edited = engineMember.items().single { it.doc.name == "from-kid-edited" }
        assertEquals(nv.vaultId, edited.vaultId, "an edit never moves an item out of its vault")

        // Role change applies without re-opening the key (grant re-delivery).
        apiOwner.setVaultMemberRole(nv.vaultId, member.userId, "reader")
        engineMember.sync()
        assertEquals("reader", member.roleFor(nv.vaultId))

        // Removal: the member's next sync purges the vault; local save fails fast.
        apiOwner.removeVaultMember(nv.vaultId, member.userId)
        engineMember.sync()
        assertTrue(engineMember.items().none { it.vaultId == nv.vaultId }, "removedGrants purged the shared items")
        assertFailsWith<CryptoException> {
            kotlinx.coroutines.runBlocking { engineMember.save(null, ItemDoc(type = "note", name = "late"), vaultId = nv.vaultId) }
        }
        // Owner unaffected.
        engineOwner.sync()
        assertTrue(engineOwner.items().any { it.vaultId == nv.vaultId })
    }

    @Test
    fun unlock_hardFails_onServerSubstitutedIdentityPub() = testApplication {
        application { andvariModule(buildServices(config(), Notifier())) }
        val api = AndvariApi("", createClient { })
        val policy = api.clientPolicy()
        val recoveryPub = Bytes.fromB64(api.recoveryPubkey())
        val password = "identity pin check password"
        val (req, _) = Account.enroll(
            bootstrap, "pin@fam.com", "Pin", password,
            policy.kdfParams, recoveryPub, policy.recoveryFingerprint, "device", crypto,
        )
        val session = api.register(req)

        // Honest keys unlock fine; a server-substituted identityPub must hard-fail even
        // though the UVK and seed decrypt correctly (spec 01 §5 pubkey substitution).
        Account.unlock(session.userId, password, session.accountKeys, crypto)
        val evil = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val tampered = session.accountKeys.copy(identityPub = Bytes.toB64(evil.publicKey))
        val e = assertFailsWith<CryptoException> { Account.unlock(session.userId, password, tampered, crypto) }
        assertTrue(e.message!!.contains("identity key mismatch"))
    }
}
