package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.writeFully
import io.silencelen.andvari.core.model.wire.WireErrors
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * In-flight upload bytes count against the vault OWNER's quota (spec 03 §9), not the
 * uploader's. Two members streaming into one owner's vault at once must not each see the whole room.
 */
class AttachmentInFlightTest {
    @Test
    fun inFlightBytes_countAgainstTheVaultsOwner() = testApplication {
        val s = TestKit.services()
        application { andvariModule(s) }
        val c = client
        Flow.finishSetup(c, s)
        val a = Flow.member(c, s, "a@example.com")
        val b = Flow.member(c, s, "b@example.com")
        val v = SharedVault(c, s, a).create()
        v.add(b)
        // The owner has 1,000 bytes of room left.
        s.db.tx { db -> db.exec("UPDATE users SET quotaAccountBytes=? WHERE userId=?", Quotas.ownedBytes(db, a.userId) + 1_000, a.userId) }
        coroutineScope {
            val ch1 = ByteChannel()
            val first = async(Dispatchers.IO) { runCatching { s.attachments.store(a.userId, uuid(), uuid(), v.vaultId, ch1) } }
            ch1.writeFully(ByteArray(24 + 600) { 1 })
            ch1.flush()
            withTimeout(5_000) { while (s.attachments.inFlightBytesOf(a.userId) < 600) delay(10) }
            // The co-member's 600 bytes on top of the owner's 600 in flight are over the owner's room.
            val ch2 = ByteChannel()
            ch2.writeFully(ByteArray(24 + 600) { 2 })
            ch2.flushAndClose()
            val second = runCatching { s.attachments.store(b.userId, uuid(), uuid(), v.vaultId, ch2) }.exceptionOrNull()
            assertTrue(second is ApiException && second.status == 413 && second.body.error == WireErrors.QUOTA_EXCEEDED, "got $second")
            ch1.flushAndClose()
            assertTrue(first.await().isSuccess, "the first upload still fits")
        }
        assertEquals(0L, s.attachments.inFlightBytesOf(a.userId))
    }
}
