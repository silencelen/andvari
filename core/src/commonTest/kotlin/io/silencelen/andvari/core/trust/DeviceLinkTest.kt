package io.silencelen.andvari.core.trust

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.crypto.CryptoException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Device linking (design 2026-11-15 §8): what `devicelink.json` cannot show. The vector grades every
 * verdict; these are the builders (which refuse whatever the other side would refuse), the scanner's
 * three-way classification, the round trips under fresh keys, and the size test E fills a bundle by.
 */
class DeviceLinkTest {
    private val crypto = createCryptoProvider()
    private val alice = Party(crypto, Ids.ALICE, 1)
    private val origin = "https://vault.example.org"
    private val secret = ByteArray(32) { (0x21 + it).toByte() }
    private val keys = DeviceLink.deriveKeys(crypto, secret)
    private val device = crypto.boxKeypairFromSeed(ByteArray(32) { (0x51 + it).toByte() })
    private val uvk = ByteArray(32) { (0x61 + it).toByte() }
    private val hashA = "ab".repeat(32)
    private val hashB = "cd".repeat(32)

    private fun bundle(contacts: Int = 2, vaults: Int = 1) = DeviceLinkBundle(
        origin, Ids.INSTANCE, Checkpoint(2, hashA), Ids.ALICE, "alice@example.com", alice.key, Ids.VAULT,
        List(contacts) { BundleContact(Ids.BOB, hashB, Ids.T0 + it) },
        List(vaults) { BundleVault(Ids.OTHER_VAULT, it.toLong(), hashA) },
        Checkpoint(7, hashB), Ids.T0,
    )

    @Test
    fun theScannerTellsTheThreePayloadsApart() {
        val deviceLink = assertNotNull(DeviceLinkUrl.compose(origin, secret))
        assertEquals("https://andvaripass.com/d#v2." + Bytes.toB64(origin.encodeToByteArray()) + "." + Bytes.toB64(secret), deviceLink)
        val invite = assertNotNull(LinkUrl.compose(origin, secret, LinkUrl.creatorFingerprint(crypto, alice.box.publicKey)))
        val hostLink = assertNotNull(LinkUrl.compose(origin, secret, null))
        val kit = assertNotNull(RecoveryKit.composeQr(origin, hashA, "alice@example.com", secret))

        assertEquals(ScanPayload.DEVICE_LINK, ScanPayload.of(deviceLink))
        assertEquals(ScanPayload.LINK, ScanPayload.of(invite))
        assertEquals(ScanPayload.LINK, ScanPayload.of(hostLink))
        assertEquals(ScanPayload.KIT, ScanPayload.of(kit))
        for (other in listOf("", "https://example.org", "andvari-kit:1:x", "v2", "otpauth://totp/x?secret=AAAA")) {
            assertEquals(ScanPayload.UNKNOWN, ScanPayload.of(other), other)
        }
        // The fragment alone decides: the path is not authenticated, so `/l` in front of three parts is still a device link.
        assertEquals(ScanPayload.DEVICE_LINK, ScanPayload.of(deviceLink.replace("/d#", "/l#")))
        assertEquals(ScanPayload.LINK, ScanPayload.of(invite.replace("/l#", "/d#")))
        // Each parser refuses the other two payloads.
        assertNull(DeviceLinkUrl.parse(invite))
        assertNull(DeviceLinkUrl.parse(kit))
        assertNull(LinkUrl.parse(deviceLink))
        assertNull(RecoveryKit.parseQr(deviceLink))
        assertNull(DeviceLinkUrl.compose("http://192.168.1.9", secret))
        assertNull(DeviceLinkUrl.compose(origin, ByteArray(31)))
    }

    @Test
    fun theClaimBuilderRefusesWhatTheExistingDeviceWouldRefuse() {
        val nPub = Bytes.toB64(device.publicKey)
        val name = assertNotNull(TrustGrammar.encodeName("Pixel 9"))
        val commitN = CodeCommit.commit(crypto, ByteArray(32) { 9 })
        val mac = DeviceLink.claimMac(crypto, keys, nPub, name, "android", commitN)
        val claim = DeviceClaim(nPub, name, "android", commitN, mac)
        val verified = assertIs<Checked.Ok<VerifiedClaim>>(DeviceLink.verifyClaim(crypto, keys, claim)).value
        assertEquals("Pixel 9", verified.deviceName)

        assertFailsWith<IllegalArgumentException> { DeviceLink.claimMac(crypto, keys, nPub, "Pixel 9", "android", commitN) }
        assertFailsWith<IllegalArgumentException> { DeviceLink.claimMac(crypto, keys, nPub, name, "beos", commitN) }
        assertFailsWith<IllegalArgumentException> { DeviceLink.claimMac(crypto, keys, nPub.dropLast(1), name, "android", commitN) }
        assertFailsWith<IllegalArgumentException> { DeviceLink.claimMac(crypto, keys, nPub, name, "android", commitN.uppercase()) }

        // The claim E fixed: the four fields, not the MAC string.
        assertTrue(claim.sameClaim(claim.copy(mac = "A".repeat(43))))
        assertFalse(claim.sameClaim(claim.copy(platform = "ios")))

        // The pickup proof is E's to compute as well, from the claim's nPub.
        val proof = DeviceLink.pickupProof(crypto, keys, nPub)
        assertEquals(64, DeviceLink.proofHash(crypto, proof).length)
        assertFailsWith<IllegalArgumentException> { DeviceLink.proofHash(crypto, "short") }
    }

    // A claim names the key `outer` is sealed to, and a
    // low-order point is 32 bytes of base64url like any key. It used to pass the claim check, and the
    // existing device then met a throw from its provider in the middle of the flow (or, with a provider
    // that does not look, sealed `outer` to a key everybody holds).
    @Test
    fun aClaimThatNamesALowOrderKey_isBadClaim_evenUnderARightMac() {
        val name = assertNotNull(TrustGrammar.encodeName("Pixel 9"))
        val commitN = CodeCommit.commit(crypto, ByteArray(32) { 9 })
        val outer = DeviceLinkOuter(origin, Ids.ALICE, "alice@example.com")
        // The claim MAC of §8.2 step 2, made by hand: the builder refuses such a key, and the point of the
        // test is that the claim is refused for its key and not because its MAC is wrong.
        fun macByHand(nPub: String): String =
            Bytes.toB64(crypto.hmacSha256(keys.macKey, "andvari/v2|device-link|claim|${keys.linkId}|$nPub|$name|android|$commitN".encodeToByteArray()))
        val own = Bytes.toB64(device.publicKey)
        assertEquals(DeviceLink.claimMac(crypto, keys, own, name, "android", commitN), macByHand(own), "the hand-made MAC is the builder's")

        val points = listOf(
            "00".repeat(32),
            "01" + "00".repeat(31),
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ec" + "ff".repeat(30) + "7f",
            "ed" + "ff".repeat(30) + "7f",
            "ee" + "ff".repeat(30) + "7f",
        ).map { assertNotNull(Bytes.fromHexLower(it)) }
        // Each point as it is listed, and with the top bit set, which X25519 ignores.
        for (key in points.flatMap { listOf(it, it.copyOf().also { k -> k[31] = (k[31].toInt() or 0x80).toByte() }) }) {
            val nPub = Bytes.toB64(key)
            assertTrue(TrustGrammar.isB64_32(nPub), "by its text it is a claim field like any other")
            val claim = DeviceClaim(nPub, name, "android", commitN, macByHand(nPub))
            assertEquals(DeviceLinkVerdict.BAD_CLAIM, DeviceLink.verifyClaim(crypto, keys, claim).verdictOrNull(), nPub)
            assertFailsWith<IllegalArgumentException>(nPub) { DeviceLink.claimMac(crypto, keys, nPub, name, "android", commitN) }
            assertFailsWith<IllegalArgumentException>(nPub) { DeviceLink.sealOuter(crypto, key, outer) }
            // What the refusal spares the existing device: its provider does not seal to such a key, and says so with a throw.
            assertFailsWith<CryptoException>(nPub) { crypto.sealTo(key, DeviceLink.encodeOuter(outer)) }
        }

        // A key next to a listed one is an ordinary key: its claim verifies, and `outer` is sealed to it.
        for (hex in listOf("02" + "00".repeat(31), "eb" + "ff".repeat(30) + "7f", "ef" + "ff".repeat(30) + "7f")) {
            val key = assertNotNull(Bytes.fromHexLower(hex))
            val nPub = Bytes.toB64(key)
            val verified = assertIs<Checked.Ok<VerifiedClaim>>(DeviceLink.verifyClaim(crypto, keys, DeviceClaim(nPub, name, "android", commitN, macByHand(nPub)))).value
            assertTrue(DeviceLink.sealOuter(crypto, verified.nPub, outer).isNotEmpty(), hex)
        }
        // And a wrong MAC over an ordinary key is still the anomaly it was.
        assertEquals(DeviceLinkVerdict.BAD_MAC, DeviceLink.verifyClaim(crypto, keys, DeviceClaim(own, name, "android", commitN, macByHand(Bytes.toB64(points[0])))).verdictOrNull())
    }

    @Test
    fun outer_roundTripsAndItsBuilderRefusesBadValues() {
        // Every dot-atom character an address may hold goes into the compact JSON as itself.
        val outer = DeviceLinkOuter(origin, Ids.ALICE, "o'brien+x/y=z{1}|~@example.com")
        val text = DeviceLink.encodeOuter(outer).decodeToString()
        assertEquals("{\"v\":2,\"origin\":\"$origin\",\"userId\":\"${Ids.ALICE}\",\"email\":\"o'brien+x/y=z{1}|~@example.com\"}", text)
        // A quote or a backslash is in no emailNorm (spec 01 §5.5: a dot-atom), so neither is ever sealed
        // or read back, however well it is escaped.
        assertFailsWith<IllegalArgumentException> { DeviceLink.sealOuter(crypto, device.publicKey, outer.copy(email = "a\"b\\c@example.com")) }
        assertNull(DeviceLink.decodeOuter("{\"v\":2,\"origin\":\"$origin\",\"userId\":\"${Ids.ALICE}\",\"email\":\"a\\\"b@example.com\"}".encodeToByteArray()))
        assertFailsWith<IllegalArgumentException> { DeviceLink.sealOuter(crypto, device.publicKey, outer.copy(email = "alice<alice@example.com>")) }
        val sealed = DeviceLink.sealOuter(crypto, device.publicKey, outer)
        val mac = DeviceLink.approveMac(crypto, keys, sealed)
        val opened = DeviceLink.openOuter(crypto, keys, device.publicKey, device.privateKey, sealed, mac, origin)
        assertEquals(outer, assertIs<Checked.Ok<DeviceLinkOuter>>(opened).value)

        val wrongMac = DeviceLink.approveMac(crypto, DeviceLink.deriveKeys(crypto, ByteArray(32) { 3 }), sealed)
        assertEquals(DeviceLinkVerdict.BAD_MAC, DeviceLink.openOuter(crypto, keys, device.publicKey, device.privateKey, sealed, wrongMac, origin).verdictOrNull())
        assertEquals(DeviceLinkVerdict.BAD_MAC, DeviceLink.openOuter(crypto, keys, device.publicKey, device.privateKey, sealed, "$mac=", origin).verdictOrNull())

        assertFailsWith<IllegalArgumentException> { DeviceLink.sealOuter(crypto, device.publicKey, outer.copy(email = "Alice@example.com")) }
        assertFailsWith<IllegalArgumentException> { DeviceLink.sealOuter(crypto, device.publicKey, outer.copy(origin = "$origin/")) }
        assertFailsWith<IllegalArgumentException> { DeviceLink.sealOuter(crypto, device.publicKey, outer.copy(userId = "not-a-uuid")) }
        assertFailsWith<IllegalArgumentException> { DeviceLink.sealOuter(crypto, ByteArray(31), outer) }
    }

    @Test
    fun bundle_roundTripsAndItsBuilderRefusesBadValues() {
        val b = bundle()
        val inner = DeviceLink.sealBundle(crypto, uvk, keys.linkId, b)
        assertEquals(b, assertIs<Checked.Ok<DeviceLinkBundle>>(DeviceLink.openBundle(crypto, uvk, keys.linkId, inner)).value)
        // Another link of the same account, or another UVK: the AD and the key refuse it.
        val otherLink = DeviceLink.deriveKeys(crypto, ByteArray(32) { 4 }).linkId
        assertEquals(DeviceLinkVerdict.BUNDLE_UNOPENABLE, DeviceLink.openBundle(crypto, uvk, otherLink, inner).verdictOrNull())
        assertEquals(DeviceLinkVerdict.BUNDLE_UNOPENABLE, DeviceLink.openBundle(crypto, ByteArray(32) { 8 }, keys.linkId, inner).verdictOrNull())

        for (bad in listOf(
            b.copy(origin = "http://vault.example.org"),
            b.copy(instanceId = "x"),
            b.copy(card = Checkpoint(-1, hashA)),
            b.copy(card = Checkpoint(2, hashA.uppercase())),
            b.copy(email = "Alice@example.com"),
            b.copy(identityPub = alice.key + "="),
            b.copy(issuedAt = 0),
            b.copy(contacts = listOf(BundleContact(Ids.BOB, hashB, 0))),
            b.copy(vaults = listOf(BundleVault("x", 1, hashA))),
            b.copy(accountState = Checkpoint(TrustGrammar.INT_CEILING, hashB)),
        )) {
            assertFalse(DeviceLink.fits(bad), bad.toString())
            assertFailsWith<IllegalArgumentException> { DeviceLink.encodeBundle(bad) }
        }
    }

    @Test
    fun bundle_theSizeTestTheExistingDeviceFillsBy() {
        // One contact entry is about 150 bytes, so a few hundred fit and a thousand do not.
        assertTrue(DeviceLink.fits(bundle(contacts = 400)))
        assertTrue(DeviceLink.encodeBundle(bundle(contacts = 400)).size <= DeviceLink.MAX_BUNDLE_BYTES)
        assertFalse(DeviceLink.fits(bundle(contacts = 1000)))
        assertFailsWith<IllegalArgumentException> { DeviceLink.encodeBundle(bundle(contacts = 1000)) }
        assertFalse(DeviceLink.fits(bundle(contacts = 0, vaults = 1001)))
        // The largest that fits is found by dropping entries from the end.
        var n = 1000
        while (!DeviceLink.fits(bundle(contacts = n))) n--
        assertTrue(n in 401..999)
        assertFalse(DeviceLink.fits(bundle(contacts = n + 1)))
    }

    @Test
    fun checkBundle_identityFirstThenThePin() {
        val b = bundle()
        val chain = listOf("11".repeat(32), "22".repeat(32), hashA)
        fun check(
            bundle: DeviceLinkBundle = b,
            session: String = Ids.ALICE,
            key: ByteArray = alice.box.publicKey,
            personal: String = Ids.VAULT,
            pinOrigin: String = origin,
            pinInstance: String = Ids.INSTANCE,
            served: List<String> = chain,
        ) = DeviceLink.checkBundle(bundle, session, key, personal, pinOrigin, pinInstance) { seq -> served.getOrNull(seq.toInt()) }

        assertNull(check())
        assertEquals(DeviceLinkVerdict.IDENTITY_MISMATCH, check(session = Ids.BOB))
        assertEquals(DeviceLinkVerdict.IDENTITY_MISMATCH, check(key = Party(crypto, Ids.BOB, 2).box.publicKey))
        assertEquals(DeviceLinkVerdict.IDENTITY_MISMATCH, check(personal = Ids.OTHER_VAULT))
        assertEquals(DeviceLinkVerdict.PIN_MISMATCH, check(pinOrigin = "https://other.example.org"))
        assertEquals(DeviceLinkVerdict.PIN_MISMATCH, check(pinInstance = Ids.OTHER_INSTANCE))
        assertEquals(DeviceLinkVerdict.PIN_MISMATCH, check(served = chain.dropLast(1) + hashB), "another hash at the checkpoint")
        assertEquals(DeviceLinkVerdict.PIN_MISMATCH, check(served = chain.dropLast(1)), "the chain still ends below the checkpoint")
        assertEquals(DeviceLinkVerdict.IDENTITY_MISMATCH, check(personal = Ids.OTHER_VAULT, pinOrigin = "https://other.example.org"))
    }
}
