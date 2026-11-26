package io.silencelen.andvari.core.client.items

import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.crypto.Attachments
import io.silencelen.andvari.core.model.wire.QuotaMeter
import io.silencelen.andvari.core.model.wire.QuotaName
import io.silencelen.andvari.core.model.wire.QuotaUse
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The check before a large copy (spec 03 §14.4), at each boundary the server's own `QuotaUseTest` walks: one below the
 * limit and exactly on it are room, one over is short by 1. And what a sync hands up, and what the sizes are.
 */
class QuotaCheckTest {
    private fun m(used: Long, limit: Long) = QuotaMeter(used, limit)

    private fun use(
        bytes: QuotaMeter = m(0, 1_000), items: QuotaMeter = m(0, 10), vaults: QuotaMeter = m(0, 2), links: QuotaMeter = m(0, 20),
    ) = QuotaUse(bytes, items, vaults, links)

    private fun room(q: QuotaUse?, size: CopySize) = QuotaCheck.room(q, size)

    private fun short(r: QuotaRoom): List<Shortfall> = assertIs<QuotaRoom.Short>(r, "short").limits

    @Test
    fun vaultsAboutToBeMadeAreCountedEachOne() {
        val q = use(vaults = m(1, 3))
        assertEquals(QuotaRoom.Room, room(q, CopySize(10, 1, newSharedVault = true, newVaults = 2)), "two more land on the limit")
        assertEquals(listOf(Shortfall(QuotaName.OWNED_SHARED_VAULTS, 1, 3, 3)), short(room(q, CopySize(10, 1, newSharedVault = true, newVaults = 3))))
        assertEquals(1L, CopySize(10, 1, newSharedVault = true).newVaults, "one when only the flag says so")
        assertEquals(0L, CopySize(10, 1).newVaults)
        assertFailsWith<IllegalArgumentException> { CopySize(10, 1, newSharedVault = false, newVaults = 2) }
        assertFailsWith<IllegalArgumentException> { CopySize(10, 1, newSharedVault = true, newVaults = 0) }
    }

    @Test
    fun accountBytesOneBelowAndOnTheLimitAreRoomAndOneOverIsShortByOne() {
        val q = use(bytes = m(900, 1_000))
        assertEquals(QuotaRoom.Room, room(q, CopySize(99, 1)))
        assertEquals(QuotaRoom.Room, room(q, CopySize(100, 1)), "landing exactly on the limit is accepted")
        val s = short(room(q, CopySize(101, 1)))
        assertEquals(listOf(Shortfall(QuotaName.ACCOUNT_BYTES, 900, 1_000, 101)), s)
        assertEquals(1, s.single().by)
        assertEquals(1_000_000 - 100, short(room(q, CopySize(1_000_000, 1))).single().by)
    }

    @Test
    fun itemsOneBelowAndOnTheLimitAreRoomAndOneOverIsShortByOne() {
        val q = use(items = m(8, 10))
        assertEquals(QuotaRoom.Room, room(q, CopySize(10, 1)))
        assertEquals(QuotaRoom.Room, room(q, CopySize(10, 2)))
        val s = short(room(q, CopySize(10, 3))).single()
        assertEquals(Shortfall(QuotaName.ITEMS, 8, 10, 3), s)
        assertEquals(1, s.by)
    }

    @Test
    fun aNewSharedVaultNeedsOneVaultOfRoomAndItsMetaMustFit() {
        assertEquals(QuotaRoom.Room, room(use(vaults = m(1, 2)), CopySize(0, 0, newSharedVault = true, metaBytes = 10)))
        val s = short(room(use(vaults = m(2, 2)), CopySize(0, 0, newSharedVault = true, metaBytes = 10))).single()
        assertEquals(Shortfall(QuotaName.OWNED_SHARED_VAULTS, 2, 2, 1), s)
        assertEquals(1, s.by)
        // No new vault: the vault meter is not grown, so it is never short, not even past its limit.
        assertEquals(QuotaRoom.Room, room(use(vaults = m(5, 2)), CopySize(10, 1)))

        // The genesis' metaBlob must fit (`used + M <= limit`): one below, on, one over.
        val b = use(bytes = m(900, 1_000))
        assertEquals(QuotaRoom.Room, room(b, CopySize(0, 0, true, 99)))
        assertEquals(QuotaRoom.Room, room(b, CopySize(0, 0, true, 100)))
        assertEquals(Shortfall(QuotaName.ACCOUNT_BYTES, 900, 1_000, 101), short(room(b, CopySize(0, 0, true, 101))).single())
        // B and M are not added: the larger of the two counts.
        assertEquals(QuotaRoom.Room, room(b, CopySize(100, 3, true, 60)))
        assertEquals(101, short(room(b, CopySize(50, 3, true, 101))).single().adds)
    }

    @Test
    fun aLimitLoweredBelowUseRefusesEveryGrowthAndNothingElse() {
        val q = use(bytes = m(1_200, 1_000), items = m(12, 10))
        val s = short(room(q, CopySize(1, 1)))
        assertEquals(listOf(QuotaName.ACCOUNT_BYTES, QuotaName.ITEMS), s.map { it.quota }, "every short limit, in the meters' order")
        assertEquals(201, s[0].by)
        assertEquals(3, s[1].by)
        assertEquals(QuotaRoom.Room, room(q, CopySize(0, 0)), "a copy that grows nothing is never short")
    }

    @Test
    fun limitsOfZeroAreShortOnEveryMeterTheCopyGrows() {
        val zero = QuotaUse(m(0, 0), m(0, 0), m(0, 0), m(0, 0))
        val s = short(room(zero, CopySize(5, 1, true, 3)))
        assertEquals(listOf(QuotaName.ACCOUNT_BYTES, QuotaName.ITEMS, QuotaName.OWNED_SHARED_VAULTS), s.map { it.quota })
        assertEquals(listOf(5L, 1L, 1L), s.map { it.by })
        assertEquals(s.first(), assertIs<QuotaRoom.Short>(room(zero, CopySize(5, 1, true, 3))).first)
    }

    @Test
    fun noNumbersOrNumbersThatCannotBeMetersAreUnknownNeverRoom() {
        assertEquals(QuotaRoom.Unknown, room(null, CopySize(1, 1)), "an older server sent none")
        for (bad in listOf(
            use(bytes = m(-1, 1_000)), use(bytes = m(0, -1)), use(items = m(-5, 10)), use(items = m(0, Long.MIN_VALUE)),
            use(vaults = m(Long.MIN_VALUE, 2)), use(links = m(0, -1)),
        )) {
            assertEquals(QuotaRoom.Unknown, room(bad, CopySize(1, 1)), "$bad")
            assertEquals(QuotaRoom.Unknown, room(bad, CopySize(0, 0)), "$bad, even for nothing")
        }
    }

    @Test
    fun numbersAtTheEdgeOfTheTypeNeverWrapRoundToRoom() {
        val top = Long.MAX_VALUE
        assertEquals(1, short(room(use(bytes = m(top, top)), CopySize(1, 0))).single().by)
        assertEquals(1, short(room(use(bytes = m(1, top)), CopySize(top, 0))).single().by, "1 + MAX overflows a Long; still short by 1")
        assertEquals(top, short(room(use(bytes = m(top, 0)), CopySize(top, 0))).single().by, "a shortfall past a Long is the largest Long")
        assertEquals(QuotaRoom.Room, room(use(bytes = m(0, top)), CopySize(top, 0)), "exactly on the largest limit")
        assertEquals(QuotaRoom.Room, room(use(bytes = m(top - 1, top), items = m(top - 1, top), vaults = m(top - 1, top)), CopySize(1, 1, true, 1)))
        val all = short(room(use(bytes = m(top, top), items = m(top, top), vaults = m(top, top)), CopySize(top, top, true, top)))
        assertEquals(listOf(top, top, 1L), all.map { it.by })
    }

    @Test
    fun aCopyOfNegativeSizeOrAMetaWithoutAVaultIsAMistakeOfTheCaller() {
        assertFailsWith<IllegalArgumentException> { CopySize(-1, 0) }
        assertFailsWith<IllegalArgumentException> { CopySize(0, -1) }
        assertFailsWith<IllegalArgumentException> { CopySize(0, 0, true, -1) }
        assertFailsWith<IllegalArgumentException> { CopySize(0, 0, false, 5) }
    }

    // ---- what a sync hands up ----

    private val honest = use(bytes = m(500, 1_000), items = m(3, 10))

    @Test
    fun eachSyncHandsUpTheQuotaItsPullServedAndTheLatestReplacesTheOne_before() = runBlocking<Unit> {
        val r = ItemRig()
        assertNull(r.engine.quota(), "the rig's first pull carried none: an older server")
        r.server.queue.add(r.response(6).copy(quota = honest))
        val report = r.engine.sync().ok()
        assertEquals(honest, report.quota)
        assertEquals(6, report.rev)
        assertEquals(honest, r.engine.quota())

        // A pull with no quota (an older server again): unknown, never the value before it.
        r.server.queue.add(r.response(7))
        assertNull(r.engine.sync().ok().quota)
        assertNull(r.engine.quota())
    }

    @Test
    fun theCheckSyncsFirstAndReadsOnlyThatPullsQuota() = runBlocking<Unit> {
        val r = ItemRig()
        r.server.queue.add(r.response(6).copy(quota = honest))
        r.engine.sync().ok()
        val pulls = r.server.syncs

        // The account filled up on another device: the fresh pull says so, not the value the device held.
        r.server.queue.add(r.response(8).copy(quota = use(bytes = m(990, 1_000), items = m(3, 10))))
        val s = short(r.engine.roomFor(CopySize(11, 1)).ok())
        assertEquals(pulls + 1, r.server.syncs, "one fresh pull")
        assertEquals(Shortfall(QuotaName.ACCOUNT_BYTES, 990, 1_000, 11), s.single())

        r.server.queue.add(r.response(9).copy(quota = honest))
        assertEquals(QuotaRoom.Room, r.engine.roomFor(CopySize(500, 7)).ok())

        // No answer: the failure is the answer; nothing is checked on the value held from before.
        r.server.offline = true
        assertIs<ItemFailure.Unreachable>(r.engine.roomFor(CopySize(1, 1)).failure())
        r.server.offline = false
        r.server.queue.add(r.response(10))
        assertEquals(QuotaRoom.Unknown, r.engine.roomFor(CopySize(1, 1)).ok(), "a pull with no quota is unknown")
    }

    @Test
    fun anImportsSizeIsExactlyWhatItsPushesCarry() = runBlocking<Unit> {
        val r = ItemRig()
        val plan = listOf(r.planned("a"), r.planned("bb", noteBytes = 1), r.planned("ccc", noteBytes = 2), r.planned("long", noteBytes = 4_000))
        val size = r.engine.importSize(plan)
        r.engine.importAll(plan).ok()
        val sent = r.server.pushes.flatten()
        assertEquals(plan.size, sent.size)
        assertEquals(sent.sumOf { it.item!!.blob.length.toLong() }, size.bytes, "B is the blob lengths as sent")
        assertEquals(plan.size.toLong(), size.items)
        assertEquals(false, size.newSharedVault)
    }

    @Test
    fun aVaultsSizeCountsItsItemsBlobsItsFilesOnceAndTheNewVaultsMeta() = runBlocking<Unit> {
        val r = ItemRig()
        val file = AttachmentRef("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "scan.pdf", 70_000, io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 1 }))
        val withFile = r.doc.copy(name = "with a file", attachments = listOf(file))
        val rows = listOf(
            r.itemRow(r.id(), r.personal, r.personalKey),
            r.itemRow(r.id(), r.personal, r.personalKey, d = withFile, rev = 7),
            r.itemRow(r.id(), r.personal, r.personalKey, d = withFile.copy(name = "same file"), rev = 8),
        )
        r.server.queue.add(r.response(9, items = rows))
        r.engine.sync().ok()

        val size = r.engine.vaultSize(r.personal)
        val stored = Attachments.wireLength(70_000) - Attachments.HEADER_BYTES
        assertEquals(rows.sumOf { it.blob!!.length.toLong() } + stored, size.bytes, "each blob as sealed, the shared file once at its stored size")
        assertEquals(3, size.items)
        assertEquals(CopySize(0, 0).metaBytes, size.metaBytes)

        val moved = r.engine.vaultSize(r.personal, newVaultName = "Moved")
        assertEquals(true, moved.newSharedVault)
        assertEquals(r.codec.sealVaultMeta(r.sharedKey, r.shared, "Moved").length.toLong(), moved.metaBytes)
        assertEquals(size.bytes, moved.bytes)
        assertEquals(0, r.engine.vaultSize(r.shared).items, "a vault this device does not read copies nothing")
    }

    /**
     * An attachment's size is what a writer of the vault declares. Each is capped at the
     * policy's limit for one file, the sum saturates, and the declared part is said, so a "short" that rests on it is
     * known as such.
     */
    @Test
    fun aDeclaredFileSizeIsCappedAtTheFileLimitAndSaidApart() = runBlocking<Unit> {
        val r = ItemRig()
        fun ref(n: Int, size: Long) = AttachmentRef("dddddddd-dddd-4ddd-8ddd-${n.toString().padStart(12, '0')}", "f$n", size, io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 1 }))
        val huge = r.doc.copy(name = "declares a huge file", attachments = listOf(ref(1, 1L shl 50)))
        val rows = listOf(r.itemRow(r.id(), r.personal, r.personalKey), r.itemRow(r.id(), r.personal, r.personalKey, d = huge, rev = 7))
        r.server.queue.add(r.response(9, items = rows))
        r.engine.sync().ok()
        val docs = rows.sumOf { it.blob!!.length.toLong() }

        val size = r.engine.vaultSize(r.personal)
        val capped = Attachments.wireLength(ItemEngine.DEFAULT_FILE_MAX_BYTES) - Attachments.HEADER_BYTES
        assertEquals(docs + capped, size.bytes, "the declared 2^50 counts as the largest file the server takes")
        assertEquals(capped, size.declaredBytes)
        val small = r.engine.vaultSize(r.personal, fileMaxBytes = 1_000)
        assertEquals(Attachments.wireLength(1_000) - Attachments.HEADER_BYTES, small.declaredBytes, "the policy's own limit")

        // Short only because of the declared file: said so. Short on what the device measured, or on items: not.
        val onDeclared = assertIs<QuotaRoom.Short>(room(use(bytes = m(0, docs + 10)), size))
        assertEquals(true, onDeclared.restsOnDeclaredSizes)
        assertEquals(false, assertIs<QuotaRoom.Short>(room(use(bytes = m(0, docs - 1)), size)).restsOnDeclaredSizes)
        assertEquals(false, assertIs<QuotaRoom.Short>(room(use(bytes = m(0, docs + 10), items = m(10, 10)), size)).restsOnDeclaredSizes)
        assertEquals(QuotaRoom.Room, room(use(bytes = m(0, Long.MAX_VALUE)), size))

        // Sums never wrap and the size never throws, whatever the files and their limit.
        assertEquals(Long.MAX_VALUE, QuotaCheck.saturatedSum(Long.MAX_VALUE, 1))
        assertEquals(Long.MAX_VALUE, QuotaCheck.saturatedSum(Long.MAX_VALUE - 1, Long.MAX_VALUE))
        assertEquals(5, QuotaCheck.saturatedSum(2, 3))
        val many = r.doc.copy(name = "many", attachments = (2..200).map { ref(it, 1L shl 50) })
        r.server.queue.add(r.response(10, items = listOf(r.itemRow(r.id(), r.personal, r.personalKey, d = many, rev = 10))))
        r.engine.sync().ok()
        val unbounded = r.engine.vaultSize(r.personal, fileMaxBytes = Long.MAX_VALUE)
        assertTrue(unbounded.bytes > 0 && unbounded.declaredBytes in 0..unbounded.bytes, "$unbounded")
        assertFailsWith<IllegalArgumentException> { CopySize(1, 1, declaredBytes = 2) }
    }
}
