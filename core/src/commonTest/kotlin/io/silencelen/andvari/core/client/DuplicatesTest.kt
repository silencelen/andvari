package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.client.Duplicates.Kind
import io.silencelen.andvari.core.client.Duplicates.clusterSignature
import io.silencelen.andvari.core.client.Duplicates.duplicateClusters
import io.silencelen.andvari.core.client.Duplicates.planDismiss
import io.silencelen.andvari.core.client.Duplicates.planKeep
import io.silencelen.andvari.core.client.Duplicates.siteKeysOf
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The Kotlin twin of `web/src/ui/duplicates.test.ts` (design 2026-08-23 §10). Clustering, the
 * exact/differs verdict, the fail-closed survivor choice and the composed merge doc are all
 * decided in [Duplicates] — pinned here so the Android screen stays a renderer/writer.
 *
 * Two web cases are deliberately NOT ported, because they pin web build facts rather than
 * behaviour: the PSL manual-chunk assertions (bundle footprint, audit F13) and the pair that
 * greps `duplicates.ts` to prove `roleFor` never regains a default. The second has a stronger
 * Kotlin equivalent that needs no test at all — [Duplicates.duplicateClusters] declares
 * `roleFor` with no default value, so omitting it is a compile error, not a silent fail-open.
 */
class DuplicatesTest {
    private var seq = 0L

    private fun login(
        itemId: String,
        username: String = "u@example.com",
        password: String = "hunter2",
        uris: List<String> = listOf("https://example.com"),
        totp: String? = null,
        passwordHistory: List<PasswordHistoryEntry> = emptyList(),
        updatedAt: Long = ++seq,
        vaultId: String = "v1",
        docOver: (ItemDoc) -> ItemDoc = { it },
    ): VaultItem = VaultItem(
        itemId = itemId,
        vaultId = vaultId,
        rev = 1,
        updatedAt = updatedAt,
        doc = docOver(
            ItemDoc(
                type = "login",
                name = itemId,
                login = LoginData(
                    username = username,
                    password = password,
                    uris = uris,
                    totp = totp,
                    passwordHistory = passwordHistory,
                ),
            ),
        ),
    )

    /** The same login sitting in a SECOND vault — the shape "Copy to vault…" and the
     *  shared-vault delete rescue mint by design. */
    private fun inVault(item: VaultItem, vaultId: String) = item.copy(vaultId = vaultId)

    /** A personal vault carries no grant, so it genuinely has no role. Spelled out at every call
     *  site because `roleFor` is REQUIRED — see the class KDoc. */
    private val noRole: (String) -> String? = { null }

    private val attachment = AttachmentRef(id = "att1", name = "f", size = 1, fileKey = "k")

    // ---- siteKeysOf ----

    @Test
    fun keysByRegistrableDomain_fallsBackToHost_andKeepsAppPackagesDistinct() {
        val keys = siteKeysOf(
            ItemDoc(
                type = "login",
                name = "x",
                // "not a uri" survives as its own key DELIBERATELY: parseSavedUri is the autofill
                // matching authority and it tolerates free-text hosts — two copies saved with the
                // same free-text uri are the same "site" to matching, so they are to the checker.
                login = LoginData(
                    uris = listOf(
                        "https://accounts.example.com/login",
                        "http://192.168.1.10:8443",
                        "androidapp://com.example.app",
                        "not a uri",
                        "",
                    ),
                ),
            ),
        )
        assertEquals(setOf("example.com", "192.168.1.10", "app:com.example.app", "not a uri"), keys)
    }

    // ---- clustering ----

    @Test
    fun clustersSameSiteAndNormalizedUsername_othersStayApart() {
        val clusters = duplicateClusters(
            listOf(
                login("a"),
                login("b", username = " U@Example.com "), // normalization joins; display keeps raw
                login("c", username = "other@example.com"),
                login("d", uris = listOf("https://elsewhere.com")),
            ),
            noRole,
        )
        assertEquals(1, clusters.size)
        assertEquals(listOf("a", "b"), clusters[0].members.map { it.itemId }.sorted())
        assertEquals(Kind.EXACT, clusters[0].kind)
        assertEquals(" U@Example.com ", clusters[0].members.first { it.itemId == "b" }.username)
    }

    @Test
    fun subdomainVsApexIsTheSameSite_andATwoSiteItemBridgesTransitively() {
        val clusters = duplicateClusters(
            listOf(
                login("a", uris = listOf("https://www.example.com")),
                login("b", uris = listOf("https://accounts.example.com")),
                login("bridge", uris = listOf("https://example.com", "https://elsewhere.com")),
                login("c", uris = listOf("https://elsewhere.com")),
            ),
            noRole,
        )
        assertEquals(1, clusters.size)
        assertEquals(4, clusters[0].members.size)
        assertEquals(listOf("elsewhere.com", "example.com"), clusters[0].sites)
    }

    @Test
    fun anItemWithNoResolvableSiteNeverClusters() {
        assertEquals(
            0,
            duplicateClusters(listOf(login("a", uris = emptyList()), login("b", uris = emptyList())), noRole).size,
        )
    }

    @Test
    fun divergingPasswordsMakeADiffersCluster_newestFirst_withNoMergePlan() {
        val clusters = duplicateClusters(
            listOf(
                login("old", password = "stale", updatedAt = 100),
                login("new", password = "fresh", updatedAt = 200),
            ),
            noRole,
        )
        assertEquals(1, clusters.size)
        assertEquals(Kind.DIFFERS, clusters[0].kind)
        // newest first — the likely-current copy leads
        assertEquals(listOf("new", "old"), clusters[0].members.map { it.itemId })
        assertNull(clusters[0].merge)
        assertNull(clusters[0].mergeRefusal) // refusals are an exact-cluster concept
    }

    // ---- the fail-closed merge plan ----

    @Test
    fun survivorIsNewest_urisUnion_favoriteSurvivesFromAnyCopy() {
        val clusters = duplicateClusters(
            listOf(
                login(
                    "old",
                    uris = listOf("https://example.com", "https://old.example.com"),
                    updatedAt = 100,
                ) { it.copy(favorite = true) },
                login("new", uris = listOf("https://example.com/login"), updatedAt = 200),
            ),
            noRole,
        )
        val plan = clusters[0].merge!!
        assertEquals("new", plan.survivorId)
        assertEquals(listOf("old"), plan.loserIds)
        assertEquals(
            listOf("https://example.com/login", "https://example.com", "https://old.example.com"),
            plan.doc.login?.uris,
        )
        assertTrue(plan.doc.favorite) // the loser's favorite is not lost
        assertEquals("hunter2", plan.doc.login?.password)
    }

    @Test
    fun theOneTotpOrNotesTextForcesTheSurvivorToItsCarrier() {
        val clusters = duplicateClusters(
            listOf(
                login("carrier", totp = "otpauth://totp/x?secret=GEZDGNBV", updatedAt = 100),
                login("newer-bare", updatedAt = 200), // newer, but merging onto it drops the code
            ),
            noRole,
        )
        assertEquals("carrier", clusters[0].merge?.survivorId)
        assertEquals("otpauth://totp/x?secret=GEZDGNBV", clusters[0].merge?.doc?.login?.totp)
    }

    @Test
    fun divergingCodes_divergingNotes_andSplitData_allRefuse() {
        val twoTotps = duplicateClusters(
            listOf(
                login("a", totp = "otpauth://totp/x?secret=GEZDGNBV"),
                login("b", totp = "otpauth://totp/x?secret=JBSWY3DP"),
            ),
            noRole,
        )
        assertNull(twoTotps[0].merge)
        assertContains(twoTotps[0].mergeRefusal!!, "different one-time codes")

        val twoNotes = duplicateClusters(
            listOf(
                login("a") { it.copy(notes = "alpha") },
                login("b") { it.copy(notes = "beta") },
            ),
            noRole,
        )
        assertContains(twoNotes[0].mergeRefusal!!, "different notes")

        // The code lives on one copy, the notes on another — no member can carry both.
        val split = duplicateClusters(
            listOf(
                login("has-totp", totp = "otpauth://totp/x?secret=GEZDGNBV"),
                login("has-notes") { it.copy(notes = "the recovery codes") },
            ),
            noRole,
        )
        assertNull(split[0].merge)
        assertContains(split[0].mergeRefusal!!, "merge by hand")
    }

    @Test
    fun attachmentsPinTheSurvivorToTheirHolder_twoHoldersRefuse() {
        val oneHolder = duplicateClusters(
            listOf(
                login("holder", updatedAt = 100) { it.copy(attachments = listOf(attachment)) },
                login("newer", updatedAt = 200),
            ),
            noRole,
        )
        assertEquals("holder", oneHolder[0].merge?.survivorId)

        val twoHolders = duplicateClusters(
            listOf(
                login("a") { it.copy(attachments = listOf(attachment)) },
                login("b") { it.copy(attachments = listOf(attachment)) },
            ),
            noRole,
        )
        assertNull(twoHolders[0].merge)
        assertContains(twoHolders[0].mergeRefusal!!, "attachments")
    }

    @Test
    fun exactClustersSortAheadOfDiffersClusters() {
        val clusters = duplicateClusters(
            listOf(
                login("d1", password = "one", uris = listOf("https://zeta.com")),
                login("d2", password = "two", uris = listOf("https://zeta.com")),
                login("e1", uris = listOf("https://alpha.com")),
                login("e2", uris = listOf("https://alpha.com")),
            ),
            noRole,
        )
        assertEquals(listOf(Kind.EXACT, Kind.DIFFERS), clusters.map { it.kind })
    }

    // ---- audit F03: the vault boundary ----

    @Test
    fun aClusterSpanningTwoVaultsIsStillReported() {
        val clusters = duplicateClusters(listOf(login("household"), inVault(login("personal-copy"), "v2")), noRole)
        assertEquals(1, clusters.size)
        assertEquals(Kind.EXACT, clusters[0].kind) // identical passwords — the copy leg clones
        assertEquals(listOf("v1", "v2"), clusters[0].members.map { it.vaultId }.sorted())
    }

    @Test
    fun andRefusesTheMerge_noSurvivor_noLoserIds_aReasonTheUiCanPrint() {
        val clusters = duplicateClusters(listOf(login("household"), inVault(login("personal-copy"), "v2")), noRole)
        assertNull(clusters[0].merge)
        assertEquals("These copies are in different vaults — merge by hand.", clusters[0].mergeRefusal)
    }

    @Test
    fun theVaultRefusalOutranksEveryDataRefusal() {
        val clusters = duplicateClusters(
            listOf(
                login("household") { it.copy(notes = "alpha") },
                inVault(login("personal-copy") { it.copy(notes = "beta") }, "v2"),
            ),
            noRole,
        )
        assertContains(clusters[0].mergeRefusal!!, "different vaults")
    }

    @Test
    fun threeCopiesAcrossTwoVaultsRefuseAsOneCluster() {
        val clusters = duplicateClusters(listOf(login("a"), login("b"), inVault(login("c"), "v2")), noRole)
        assertEquals(1, clusters.size)
        assertEquals(3, clusters[0].members.size)
        assertNull(clusters[0].merge)
        assertContains(clusters[0].mergeRefusal!!, "different vaults")
    }

    @Test
    fun sameVaultClustersAreUnaffected() {
        val clusters = duplicateClusters(listOf(login("a", updatedAt = 100), login("b", updatedAt = 200)), noRole)
        assertEquals("b", clusters[0].merge?.survivorId)
        assertEquals(listOf("a"), clusters[0].merge?.loserIds)
    }

    @Test
    fun aViewOnlyVaultRefusesToo_aDeniedRemoveWouldHalfCompleteTheMerge() {
        val readerVault = duplicateClusters(
            listOf(login("a", updatedAt = 100), login("b", updatedAt = 200)),
        ) { "reader" }
        assertNull(readerVault[0].merge)
        assertContains(readerVault[0].mergeRefusal!!, "only view")
        // No reader-held item can ever reach loserIds — the invariant, stated as an assertion.
        assertEquals(emptyList(), readerVault.flatMap { it.merge?.loserIds ?: emptyList() })
    }

    @Test
    fun writerOwnerAndNoRoleAllMergeNormally() {
        for (role in listOf("writer", "owner", null)) {
            val clusters = duplicateClusters(
                listOf(login("a", updatedAt = 100), login("b", updatedAt = 200)),
            ) { role }
            assertEquals(listOf("a"), clusters[0].merge?.loserIds, "role $role")
        }
    }

    // ---- planKeep: the differs resolution ----

    private fun differsCluster() = listOf(
        login("stale", password = "old-pass", updatedAt = 10),
        login(
            "current",
            password = "new-pass",
            uris = listOf("https://example.com", "https://sso.example.com"),
            updatedAt = 20,
        ),
        login("older", password = "ancient", updatedAt = 5),
    )

    @Test
    fun keepsTheChosenCopy_unionsUris_retiresEveryDistinctLosingPassword() {
        val items = differsCluster()
        val plan = planKeep(items, listOf("stale", "current", "older"), "current", noRole, 777)
        assertNull(plan.keepRefusal)
        assertEquals("current", plan.keep?.survivorId)
        assertEquals(listOf("stale", "older"), plan.keep?.loserIds) // newest-first
        assertEquals("new-pass", plan.keep?.doc?.login?.password)
        assertEquals(listOf("https://example.com", "https://sso.example.com"), plan.keep?.doc?.login?.uris)
        assertEquals(
            listOf(
                PasswordHistoryEntry(password = "old-pass", retiredAt = 777),
                PasswordHistoryEntry(password = "ancient", retiredAt = 777),
            ),
            plan.keep?.doc?.login?.passwordHistory,
        )
    }

    @Test
    fun neverDuplicatesAPasswordAlreadyHeld() {
        val items = listOf(
            login(
                "a",
                password = "keep-me",
                passwordHistory = listOf(PasswordHistoryEntry("old-pass", 1)),
                updatedAt = 30,
            ),
            login("b", password = "old-pass", updatedAt = 20), // already in history → not re-added
            login("c", password = "twin", updatedAt = 10),
            login("d", password = "twin", updatedAt = 5), //     second carrier of "twin" → once
        )
        val plan = planKeep(items, listOf("a", "b", "c", "d"), "a", noRole, 9)
        assertEquals(
            listOf(
                PasswordHistoryEntry(password = "old-pass", retiredAt = 1),
                PasswordHistoryEntry(password = "twin", retiredAt = 9),
            ),
            plan.keep?.doc?.login?.passwordHistory,
        )
    }

    @Test
    fun planKeepRefusesCrossVault_readers_divergingCodesNotes_andLosersWithAttachments() {
        val base = differsCluster()
        assertContains(
            planKeep(
                listOf(base[0], inVault(base[1], "v2"), base[2]),
                listOf("stale", "current", "older"), "current", noRole, 0,
            ).keepRefusal!!,
            "different vaults",
        )
        assertContains(
            planKeep(base, listOf("stale", "current", "older"), "current", { "reader" }, 0).keepRefusal!!,
            "only view",
        )
        val withTotp = listOf(
            login("stale", password = "old", totp = "otpauth://totp/x?secret=GEZDGNBV", updatedAt = 10),
            login("current", password = "new", updatedAt = 20),
        )
        assertContains(planKeep(withTotp, listOf("stale", "current"), "current", noRole, 0).keepRefusal!!, "one-time codes")

        val withNotes = listOf(
            login("stale", password = "old", updatedAt = 10) { it.copy(notes = "loser-only note") },
            login("current", password = "new", updatedAt = 20),
        )
        assertContains(planKeep(withNotes, listOf("stale", "current"), "current", noRole, 0).keepRefusal!!, "different notes")

        val withAtt = listOf(
            login("stale", password = "old", updatedAt = 10) { it.copy(attachments = listOf(attachment)) },
            login("current", password = "new", updatedAt = 20),
        )
        assertContains(planKeep(withAtt, listOf("stale", "current"), "current", noRole, 0).keepRefusal!!, "attachments")
    }

    @Test
    fun aMemberIdMissingFromTheLiveItemsRefuses() {
        assertContains(
            planKeep(differsCluster(), listOf("stale", "current", "vanished"), "current", noRole, 0).keepRefusal!!,
            "changed under you",
        )
    }

    // ---- clusterSignature / dupeAck ----

    @Test
    fun dismissedOnlyWhileEveryMemberCarriesTheCurrentConstitutionsSignature() {
        val sig = clusterSignature(listOf("a", "b"))
        val dismissedPair = listOf(
            login("a", updatedAt = 10) { it.copy(dupeAck = sig) },
            login("b", updatedAt = 20) { it.copy(dupeAck = sig) },
        )
        assertTrue(duplicateClusters(dismissedPair, noRole)[0].dismissed)
        // A third copy arrives: same site+user, new membership → new signature → resurfaces.
        val withNewcomer = dismissedPair + login("c", updatedAt = 30)
        val c = duplicateClusters(withNewcomer, noRole)[0]
        assertEquals(false, c.dismissed)
        assertEquals(clusterSignature(listOf("a", "b", "c")), c.signature)
    }

    @Test
    fun signatureIsOrderInsensitive() {
        assertEquals(clusterSignature(listOf("a", "b")), clusterSignature(listOf("b", "a")))
    }

    @Test
    fun planDismissStampsEveryMember_emptySignatureClearsTheKey() {
        val items = listOf(login("a"), login("b"))
        val sig = clusterSignature(listOf("a", "b"))
        val writes = planDismiss(items, listOf("a", "b"), sig, noRole).writes!!
        assertEquals(listOf(sig, sig), writes.map { it.doc.dupeAck })
        val restamped = writes.mapIndexed { i, w -> items[i].copy(doc = w.doc) }
        val cleared = planDismiss(restamped, listOf("a", "b"), "", noRole)
        assertTrue(cleared.writes!!.all { it.doc.dupeAck == null })
    }

    @Test
    fun planDismissAllowsCrossVaultButRefusesAReaderVault() {
        val items = listOf(login("a"), inVault(login("b"), "v2"))
        val sig = clusterSignature(listOf("a", "b"))
        assertEquals(2, planDismiss(items, listOf("a", "b"), sig, noRole).writes?.size)
        assertContains(
            planDismiss(items, listOf("a", "b"), sig) { v -> if (v == "v2") "reader" else null }.dismissRefusal!!,
            "only view",
        )
    }
}
