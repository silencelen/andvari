package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.UsageKey
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.AccountKeys
import io.silencelen.andvari.core.model.RegisterRequest
import io.silencelen.andvari.core.model.WireGrant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Audit H64 — the usage-ledger key must not follow a server label.
 *
 * `Vault.type` is server PLAINTEXT (spec 02 §4) bound into no AD, and after enrollment nothing
 * the client holds says which vault is its own: `personalVaultId` is rebuilt on every unlock from
 * the first row the server labels `personal` whose key the client happens to hold. Since
 * `usageKey = HKDF(VK(personalVault), "andvari/v1|usage")` and `Ad.usage(userId)` is public, a
 * hostile server that withheld the real personal row and relabelled a SHARED vault the victim is
 * merely a member of would have moved the ledger under a key every OTHER member of that vault
 * already holds — a colluding housemate could then read the victim's per-item behavioural log.
 *
 * The owner's decision is the cheap refusal: never adopt a vault whose VK arrived by member grant
 * (`sealedVk`) as the personal vault, on core and web identically. These cases pin that against
 * the real crypto — including the co-member decrypt attempt the row is actually about — so a
 * revert to "first row the server calls personal" fails here rather than in the field.
 */
class UsagePersonalVaultProvenanceTest {

    private val crypto = createCryptoProvider()
    private val kdf = KdfParams(ops = 1, memBytes = 8192) // test-speed argon2id
    private val password = "correct horse battery staple"

    private class Enrolled(val reg: RegisterRequest, val account: Account, val keys: AccountKeys)

    private fun enroll(email: String): Enrolled {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val fp = Escrow.fingerprint(crypto, recovery.publicKey)
        val (reg, account) = Account.enroll("inv", email, email, password, kdf, recovery.publicKey, fp, "dev", crypto)
        return Enrolled(
            reg, account,
            AccountKeys(
                kdfSalt = reg.kdfSalt,
                kdfParams = reg.kdfParams,
                wrappedUvk = reg.wrappedUvk,
                encryptedIdentitySeed = reg.encryptedIdentitySeed,
                identityPub = reg.identityPub,
                escrowFingerprint = reg.escrow!!.fingerprint,
            ),
        )
    }

    /** The personal-vault owner grant a sync delivers: wrappedVk under the account's own UVK. */
    private fun personalGrant(e: Enrolled) = WireGrant(
        vaultId = e.reg.personalVault.vaultId,
        userId = e.reg.userId,
        role = "owner",
        wrappedVk = e.reg.personalVault.wrappedVk,
        rev = 1,
    )

    @Test
    fun aRelabelledMemberGrantNeverBecomesThePersonalVault() {
        val victim = enroll("victim@example.com")
        val housemate = enroll("housemate@example.com")

        // A genuine shared vault the victim is a WRITER of — the household vault, nothing exotic.
        val shared = housemate.account.buildCreateSharedVault("Household")
        val memberGrant = WireGrant(
            vaultId = shared.vaultId, userId = victim.reg.userId, role = "writer",
            wrappedVk = "", rev = 3, sealedVk = housemate.account.wrapVkForMember(victim.account.identityPub, shared.vaultId),
        )

        // A fresh unlock: personalVaultId is EMPTY and must be rediscovered from the feed. This is
        // the whole attack surface — the enrolled Account object already knows its own vault.
        val device = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        assertEquals("", device.personalVaultId, "a fresh unlock starts with no personal vault")

        // The hostile feed: the member grant lands, and the shared vault row arrives RELABELLED
        // type="personal" while the real personal row is withheld.
        device.addGrant(memberGrant)
        assertTrue(device.hasVault(shared.vaultId), "the member grant is still honoured — the vault opens")
        assertTrue(device.keyArrivedByMemberGrant(shared.vaultId), "and its key is remembered as member-granted")
        device.setPersonalVault(shared.vaultId)

        assertEquals("", device.personalVaultId, "a member-granted vault must never be adopted as personal")
        // Fail-closed, per the owner's decision: no personal vault means no ledger, which callers
        // already render as "—". Silently keying the ledger from the housemates' VK is the bug.
        assertTrue(runCatching { device.sealUsage("{}".encodeToByteArray()) }.isFailure, "no personal vault ⇒ no ledger, not a ledger under the wrong key")

        // The real personal row finally arrives (or the server stops lying): now it is adopted.
        device.addGrant(personalGrant(victim))
        assertFalse(device.keyArrivedByMemberGrant(victim.reg.personalVault.vaultId), "a personal grant is wrappedVk under our own UVK")
        device.setPersonalVault(victim.reg.personalVault.vaultId)
        assertEquals(victim.reg.personalVault.vaultId, device.personalVaultId)

        // The point of the row: the co-member cannot open the ledger. `spy` stands in for any other
        // member of that shared vault — it holds the shared VK exactly as they do, and the AD is
        // public, so if the key had moved this open would succeed.
        val ledger = device.sealUsage("""{"item-1":{"lastUsedAt":1,"useCount":2}}""".encodeToByteArray())
        val spy = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val sharedVk = SharedGrant.open(
            crypto, spy.publicKey, spy.privateKey, shared.vaultId,
            Bytes.fromB64(housemate.account.wrapVkForMember(spy.publicKey, shared.vaultId)),
        )
        val coMemberKey = UsageKey.usageKey(crypto, sharedVk)
        assertTrue(
            runCatching { Envelope.openB64(crypto, coMemberKey, ledger, Ad.usage(victim.reg.userId)) }.isFailure,
            "a co-member of the relabelled vault must not be able to open the victim's usage ledger",
        )
        assertEquals(
            """{"item-1":{"lastUsedAt":1,"useCount":2}}""",
            device.openUsage(ledger).decodeToString(),
            "and the owner still reads it, under the personal VK",
        )
    }

    @Test
    fun theRefusalSurvivesTheHostileORDERINGAndTheHonestOneIsUntouched() {
        val victim = enroll("order@example.com")
        val housemate = enroll("order-mate@example.com")
        val shared = housemate.account.buildCreateSharedVault("Household")
        val memberGrant = WireGrant(
            vaultId = shared.vaultId, userId = victim.reg.userId, role = "reader",
            wrappedVk = "", rev = 2, sealedVk = housemate.account.wrapVkForMember(victim.account.identityPub, shared.vaultId),
        )

        // Honest ordering first: the personal vault is adopted, and a later relabel of the shared
        // vault cannot displace it (first-writer-wins already covers this, but a future refactor
        // that made the LAST label win would silently reintroduce the row).
        val honest = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        honest.addGrant(personalGrant(victim))
        honest.addGrant(memberGrant)
        honest.setPersonalVault(victim.reg.personalVault.vaultId)
        honest.setPersonalVault(shared.vaultId)
        assertEquals(victim.reg.personalVault.vaultId, honest.personalVaultId)

        // Hostile ordering: the relabelled shared vault is offered FIRST and repeatedly. It is
        // refused every time, and the real vault is still adoptable afterwards — the refusal must
        // not burn the one-shot slot ("first writer wins" would otherwise lock in an empty string
        // only by accident of the isEmpty() check running second).
        val attacked = Account.unlock(victim.reg.userId, password, victim.keys, crypto)
        attacked.addGrant(memberGrant)
        repeat(3) { attacked.setPersonalVault(shared.vaultId) }
        assertEquals("", attacked.personalVaultId)
        attacked.addGrant(personalGrant(victim))
        attacked.setPersonalVault(victim.reg.personalVault.vaultId)
        assertEquals(victim.reg.personalVault.vaultId, attacked.personalVaultId)
        assertNotEquals(shared.vaultId, attacked.personalVaultId)

        // Revocation forgets the provenance with the key (a re-add must re-decide from the new
        // grant, not from a stale annotation of a vaultId that is never recycled anyway).
        attacked.removeVault(shared.vaultId)
        assertFalse(attacked.keyArrivedByMemberGrant(shared.vaultId))
    }
}
