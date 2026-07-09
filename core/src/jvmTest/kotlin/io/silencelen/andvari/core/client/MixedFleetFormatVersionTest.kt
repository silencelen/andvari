package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.crypto.Ad
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.Envelope
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.SharedGrant
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.ItemVersion
import io.silencelen.andvari.core.model.WireGrant
import io.silencelen.andvari.core.model.WireItem
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The 0.2.x MSI's item model at its build commit (0c52a2d): plain generated serializers —
 *  no ExtrasOverlay (F32 landed in 0.4.0), no formatVersion fail-closed gate — decoded with
 *  ignoreUnknownKeys and rebuilt field-by-field on write. This is the one fielded decode
 *  that cannot round-trip an unknown key. */
@Serializable
private data class Legacy02xLogin(
    val username: String? = null,
    val password: String? = null,
    val uris: List<String> = emptyList(),
    val totp: String? = null,
)

@Serializable
private data class Legacy02xDoc(
    val type: String,
    val name: String,
    val notes: String? = null,
    val favorite: Boolean = false,
    val login: Legacy02xLogin? = null,
)

/**
 * Mixed-fleet formatVersion proofs for cards (design doc 2026-07-09, "the degradation
 * gate") — the WHY of fv2, pinned as executable fact:
 *
 *  - the fielded 0.2.x desktop MSI decodes any fv into pre-overlay typed fields and has an
 *    AUTOMATIC pull-side write path (materializeConflict), so a card that ever conflicts
 *    would be re-sealed from a card-stripped decode with no user action. The only plaintext
 *    signal a zero-knowledge server has to refuse that rewrite is the formatVersion — hence
 *    cards seal at 2 and the server refuses per-item fv downgrades (the refusal itself is
 *    the server module's test; this file pins the loss it prevents).
 *  - every 0.4.0–0.6.0 client (ITEM_FORMAT_VERSION = 1) fails CLOSED on an fv2 card before
 *    the envelope opens — invisible-not-degraded, envelope retained, retried on hydrate.
 *  - this build seals card docs at the fv2 floor and re-seals every item monotonically at
 *    maxOf(docFloor, the fv it was decrypted at), so no client of this generation can emit
 *    the downgrade the server refuses.
 */
class MixedFleetFormatVersionTest {
    private val crypto = createCryptoProvider()
    /** Mirrors Account's private json config (the real item-doc encode/decode path). */
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private val cardDoc = ItemDoc(
        type = "card", name = "Blue Visa",
        card = CardData(
            cardholderName = "Jacob Cardholder", number = "4242424242424242",
            expMonth = "12", expYear = "2027", securityCode = "123", brand = "visa",
        ),
    )
    private val loginDoc = ItemDoc(type = "login", name = "GitHub", login = LoginData(username = "jacob", password = "hunter2"))

    /** The ceiling is 2 for the 0.7.0 generation — a further bump is a design event
     *  (per-doc floors + the server monotonic guard must be revisited), not a refactor. */
    @Test
    fun itemFormatVersionConst_pinnedAt2() {
        assertEquals(2, Account.ITEM_FORMAT_VERSION)
    }

    @Test
    fun docFloor_cardDocs2_loginsNotes1() {
        assertEquals(2, Account.docFloor(cardDoc))
        // type alone floors: a card whose fields were stripped must still never seal below 2.
        assertEquals(2, Account.docFloor(ItemDoc(type = "card", name = "husk")))
        // card data floors regardless of declared type.
        assertEquals(2, Account.docFloor(ItemDoc(type = "login", name = "l", card = CardData(number = "4242424242424242"))))
        assertEquals(1, Account.docFloor(loginDoc))
        assertEquals(1, Account.docFloor(ItemDoc(type = "note", name = "n")))
    }

    /** Cards seal at 2, logins at 1; the fv is inside the AD, so the server cannot re-declare
     *  an envelope's version without the open failing (the downgrade guard's crypto belt). */
    @Test
    fun encryptItem_sealsAtTheFloor_andBindsFvIntoAd() {
        val account = enrolledAccount()
        val cardId = account.newItemId()
        val up = account.encryptItem(account.personalVaultId, cardId, cardDoc)
        assertEquals(2, up.formatVersion)

        val back = account.decryptItem(wire(account.personalVaultId, cardId, up.blob, fv = 2))
        assertEquals("4242424242424242", back.card?.number)
        assertEquals("visa", back.card?.brand)
        // Same blob re-declared fv1: the ceiling gate passes but the AD no longer matches.
        assertFailsWith<CryptoException> { account.decryptItem(wire(account.personalVaultId, cardId, up.blob, fv = 1)) }

        assertEquals(1, account.encryptItem(account.personalVaultId, account.newItemId(), loginDoc).formatVersion)
    }

    /**
     * THE fatal (design doc): the 0.2.x decode of the EXACT plaintext a 0.7.0 client seals
     * for a card comes back without the card — a name-only husk its automatic conflict path
     * would push, declaring ITS formatVersion (1) over the row's 2. That 2→1 downgrade is
     * the only plaintext-visible trace, which is why fv2 (not the 0.4.0 extras overlay,
     * which the 0.2.x build predates) is the required mechanism.
     */
    @Test
    fun legacy02xDecode_dropsTheCard_onItsAutomaticRewritePath() {
        val account = enrolledAccount()
        val itemId = account.newItemId()
        val up = account.encryptItem(account.personalVaultId, itemId, cardDoc)
        // The sealed plaintext, via the real path: decrypt, re-encode with Account's config.
        val plaintext = json.encodeToString(ItemDoc.serializer(), account.decryptItem(wire(account.personalVaultId, itemId, up.blob, fv = 2)))
        assertTrue("\"card\"" in plaintext)

        val legacy = Json { ignoreUnknownKeys = true } // the 0.2.x decode: no overlay, no fv gate
        val husk = legacy.encodeToString(Legacy02xDoc.serializer(), legacy.decodeFromString(Legacy02xDoc.serializer(), plaintext))
        val huskObj = Json.parseToJsonElement(husk).jsonObject
        assertNull(huskObj["card"], "the pre-overlay decode must DROP the card — the loss fv2 exists to make refusable")
        assertEquals("Blue Visa", huskObj.getValue("name").jsonPrimitive.content) // name-only ghost row
        assertEquals("card", huskObj.getValue("type").jsonPrimitive.content)

        // The husk re-seals under the 0.2.x const: a 2→1 downgrade on an existing row —
        // exactly the write pattern the server's monotonic-fv guard refuses.
        val legacyItemFormatVersion = 1
        assertTrue(legacyItemFormatVersion < up.formatVersion)
    }

    /**
     * Every fielded 0.4.0–0.6.0 client compiled ITEM_FORMAT_VERSION = 1 into the same gate
     * this build carries: the check runs on the wire fv BEFORE the envelope opens (needs no
     * key) and throws the skippable CryptoException the sync paths runCatch into
     * "undecryptable, keep the envelope, retry on hydrate" — the shipped needs-update
     * banner. An fv2 card is therefore invisible-not-degraded there, never editable, never
     * re-sealed. The gate is version-relative — proven against this build's own ceiling too.
     */
    @Test
    fun fv1Build_failsClosed_onAnFv2Card() {
        val account = enrolledAccount()
        val itemId = account.newItemId()
        val up = account.encryptItem(account.personalVaultId, itemId, cardDoc)
        val w = wire(account.personalVaultId, itemId, up.blob, fv = up.formatVersion)

        // The fv1 build's gate, verbatim with its const inlined: fires before any crypto.
        val fv1BuildCeiling = 1
        val e = assertFailsWith<CryptoException> {
            if (w.formatVersion > fv1BuildCeiling) throw CryptoException("item formatVersion ${w.formatVersion} is newer than this client supports")
            account.decryptItem(w) // unreached on an fv1 build — asserts the predicate fires
        }
        assertTrue("formatVersion" in (e.message ?: ""))

        // This build's real gate: identical fail-closed behavior one past ITS ceiling.
        val tooNew = assertFailsWith<CryptoException> {
            account.decryptItem(wire(account.personalVaultId, itemId, up.blob, fv = Account.ITEM_FORMAT_VERSION + 1))
        }
        assertTrue("formatVersion" in (tooNew.message ?: ""), "gate must name the version, got: ${tooNew.message}")
    }

    /**
     * Monotonic reseal: an item that ARRIVED at fv2 must re-seal at ≥ 2 even when its doc's
     * floor is 1 (a future generation may legally seal any type above the floor; re-emitting
     * a lower fv is the downgrade the server refuses). The fv2-login writer is simulated
     * with a test-held VK delivered through the real sealed-grant path.
     */
    @Test
    fun reseal_isMonotonic_neverBelowTheDecryptedFv() {
        val member = enrolledAccount()
        val vaultId = "44444444-4444-4444-8444-444444444444"
        val vk = crypto.randomBytes(32)
        member.addGrant(WireGrant(vaultId, member.userId, "writer", wrappedVk = "", rev = 1, sealedVk = Bytes.toB64(SharedGrant.seal(crypto, member.identityPub, vaultId, vk))))

        val itemId = member.newItemId()
        val fv2LoginBlob = Envelope.sealB64(crypto, vk, json.encodeToString(ItemDoc.serializer(), loginDoc).encodeToByteArray(), Ad.item(vaultId, itemId, 2))
        val decrypted = member.decryptItem(WireItem(itemId, vaultId, 5, 0, 0, false, false, 2, emptyList(), fv2LoginBlob))

        // Rename → re-seal: floor(login) = 1 but the item arrived at 2 → stays 2.
        assertEquals(2, member.encryptItem(vaultId, itemId, decrypted.copy(name = "renamed")).formatVersion)

        // Viewing an OLDER archived version (fv1) must not lower the memory — item-history
        // restore is an ordinary put and must not mint a refused downgrade.
        val fv1Blob = Envelope.sealB64(crypto, vk, json.encodeToString(ItemDoc.serializer(), loginDoc).encodeToByteArray(), Ad.item(vaultId, itemId, 1))
        member.decryptItemVersion(vaultId, itemId, ItemVersion(rev = 4, blob = fv1Blob, formatVersion = 1, archivedAt = 0))
        assertEquals(2, member.encryptItem(vaultId, itemId, decrypted).formatVersion)

        // No cross-item bleed: a fresh login in the same vault still seals at its floor.
        assertEquals(1, member.encryptItem(vaultId, member.newItemId(), loginDoc).formatVersion)

        // Card round trip: decrypted fv2 card re-seals at 2 (floor and memory agree).
        val cardId = member.newItemId()
        val cardUp = member.encryptItem(vaultId, cardId, cardDoc)
        val cardBack = member.decryptItem(WireItem(cardId, vaultId, 6, 0, 0, false, false, cardUp.formatVersion, emptyList(), cardUp.blob))
        assertEquals(2, member.encryptItem(vaultId, cardId, cardBack.copy(favorite = true)).formatVersion)
    }

    private fun wire(vaultId: String, itemId: String, blob: String?, fv: Int) = WireItem(
        itemId = itemId, vaultId = vaultId, rev = 1, createdAt = 0, updatedAt = 0,
        deleted = false, conflict = false, formatVersion = fv, attachmentIds = emptyList(), blob = blob,
    )

    /** Offline enrollment (no server) with minimum-cost KDF — these tests exercise the
     *  formatVersion mechanics, not argon2id. Same shape as ItemDocVectorsTest. */
    private fun enrolledAccount(): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        val (_, account) = Account.enroll(
            inviteToken = "mixed-fleet-test",
            email = "fleet@x.com",
            displayName = "MixedFleet",
            password = "mixed fleet fv password",
            params = KdfParams(ops = 1, memBytes = 8 * 1024 * 1024),
            recoveryPublicKey = recovery.publicKey,
            recoveryFingerprint = Escrow.fingerprint(crypto, recovery.publicKey),
            deviceName = "fleet-device",
            crypto = crypto,
        )
        return account
    }
}
