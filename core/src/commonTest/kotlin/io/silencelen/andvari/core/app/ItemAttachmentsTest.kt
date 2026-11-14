package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.crypto.Escrow
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** A file's name as the app shows and saves it, and the records only this account can write (round-9 review 1, 2). */
class ItemAttachmentsTest {
    private val crypto = createCryptoProvider()

    private fun account(email: String): Account {
        val recovery = crypto.boxKeypairFromSeed(crypto.randomBytes(32))
        return Account.enroll("invite", email, "u", "correct horse battery staple 42!", KdfParams(ops = 1, memBytes = 8192), recovery.publicKey, Escrow.fingerprint(crypto, recovery.publicKey), "device", crypto).account
    }

    @Test
    fun aNameIsNeverAPathNorHidesWhatItIs() {
        val safe = AttachmentRules::safeFileName
        assertEquals("x.plist", safe("../../Library/Preferences/x.plist"), "the last part of a path")
        assertEquals("evil.txt", safe("..\\..\\evil.txt"), "a Windows path too")
        assertEquals("File", safe(".."))
        assertEquals("File", safe("../.."))
        assertEquals("File", safe("   "))
        assertEquals("File", safe(""))
        assertEquals("hidden", safe(".hidden"), "never a hidden file")
        assertEquals("report.pdf", safe("report.pdf..  "), "nor trailing dots")
        assertEquals("photogpj.exe", safe("photo\u202Egpj.exe"), "a right-to-left override goes, so the real extension shows")
        assertEquals("abc.pdf", safe("a\u0000b\nc\u200B.pdf"), "control and zero-width characters go")
        assertEquals("a\u0301b.pdf", safe("a\u0301b.pdf"), "combining marks stay")
        assertEquals("2026-11-13 14-05.pdf", safe("2026-11-13 14:05.pdf"), "a colon would read as a slash in Files")
        assertEquals("Квитанция.pdf", safe("Квитанция.pdf"), "any script")
        val long = safe("a".repeat(500) + ".pdf")
        assertEquals(AttachmentRules.MAX_NAME_CHARS, long.length)
        assertTrue(long.endsWith(".pdf"), "a long name keeps its extension")
        assertEquals(AttachmentRules.MAX_NAME_CHARS, safe("b".repeat(500)).length)
    }

    @Test
    fun aLocalRecordOpensOnlyForTheAccountThatWroteItAndOnlyForItsPurpose() {
        val me = account("u@example.com")
        val other = account("co-member@example.com")
        val plain = "kept".encodeToByteArray()
        val record = me.sealLocalRecord("kept-saves", plain)
        assertContentEquals(plain, me.openLocalRecord("kept-saves", record))
        assertNull(me.openLocalRecord("move-memos", record), "a record is bound to its purpose")
        // Anyone holding the public key can make a sealed box that opens for this account: without the MAC it is refused.
        val forged = crypto.sealTo(me.identityPub, plain)
        assertContentEquals(plain, me.openQueuedSave(forged), "it would open")
        assertNull(me.openLocalRecord("kept-saves", forged), "but it is not a local record")
        assertNull(me.openLocalRecord("kept-saves", ByteArray(32) + forged), "nor with a made-up MAC")
        assertNull(me.openLocalRecord("kept-saves", other.sealLocalRecord("kept-saves", plain)), "nor one another account made")
        val tampered = record.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertNull(me.openLocalRecord("kept-saves", tampered))
        assertNull(me.openLocalRecord("kept-saves", ByteArray(10)))
    }
}
