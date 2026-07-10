package io.silencelen.andvari.server

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * F56 (guided-importers perf pack, 2026-07-09 review finding [10]): the sync pull's item
 * query was rewritten from a `(i.rev>? OR g.rev>?)` OR-join — which loses `idx_items_vault_rev`'s
 * rev bound and scans every granted item on every pull — into two disjoint UNION ALL arms.
 * A wrong or duplicated row here is SILENT sync corruption, so this test pins the row-set
 * equivalence directly: the ORIGINAL OR-join is embedded verbatim as the oracle, and both
 * queries run against the SAME seeded db (real migration-built schema, including the v5
 * index) across every meaningful `since` value and every row shape the reviewer named —
 * shared vaults, a revoked grant, a freshly-bumped grant (new member / role change),
 * tombstones, and conflict rows. Same rows, no dups, every since: the refactor is safe, and
 * this fails the moment a future edit diverges the two.
 */
class PullQueryEquivalenceTest {
    private val tmpDir: File = Files.createTempDirectory("andvari-pullq").toFile()

    /** The item query as it must run in production (Repo.pull) — kept in sync with Repo.kt. */
    private val PRODUCTION = """
        SELECT i.itemId FROM items i JOIN grants g ON g.vaultId=i.vaultId
        WHERE g.userId=? AND g.revokedAt IS NULL AND i.rev>?
        UNION ALL
        SELECT i.itemId FROM items i JOIN grants g ON g.vaultId=i.vaultId
        WHERE g.userId=? AND g.revokedAt IS NULL AND g.rev>? AND i.rev<=?
    """.trimIndent()

    /** The original OR-join (pre-2026-07-09) — the equivalence ORACLE, embedded verbatim. */
    private val ORACLE = """
        SELECT i.itemId FROM items i JOIN grants g ON g.vaultId=i.vaultId
        WHERE g.userId=? AND g.revokedAt IS NULL AND (i.rev>? OR g.rev>?)
    """.trimIndent()

    @Test
    fun unionAll_pull_returns_exactly_the_orJoin_rowset_across_shapes_and_since() {
        val dbFile = File(tmpDir, "pullq-${System.nanoTime()}.db")
        Db(dbFile.absolutePath).use { db ->
            db.tx { c ->
                // Two users; `me` is the caller, `other` proves per-user grant scoping.
                for (u in listOf("me", "other")) {
                    c.exec(
                        """INSERT INTO users(userId,email,displayName,kdfSalt,kdfParams,verifier,
                           wrappedUvk,identityPub,encryptedIdentitySeed,createdAt)
                           VALUES(?,?,?,'s','p','v','w','ip','eis',0)""",
                        u, "$u@x.com", u,
                    )
                }
                // Vaults: vp = my personal (grant rev 1), vs = shared with me at a BUMPED grant
                // rev (a re-add / role change), vr = a vault my grant to which was REVOKED,
                // vo = a vault only `other` holds.
                for (v in listOf("vp", "vs", "vr", "vo")) {
                    c.exec("INSERT INTO vaults(vaultId,type,rev,metaBlob,createdAt) VALUES(?,?,1,'m',0)", v, "shared")
                }
                // grant rev is the load-bearing arm-2 driver: vs at rev 50 backfills its items
                // that sit at or below `since`; vp at rev 1 never triggers arm 2.
                c.exec("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev,revokedAt) VALUES('vp','me','owner','w',1,NULL)")
                c.exec("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev,revokedAt) VALUES('vs','me','writer','w',50,NULL)")
                c.exec("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev,revokedAt) VALUES('vr','me','writer','w',20,999)") // REVOKED
                c.exec("INSERT INTO grants(vaultId,userId,role,wrappedVk,rev,revokedAt) VALUES('vo','other','owner','w',1,NULL)")

                // Items across the rev axis + every shape. deleted=1 (tombstone) and conflict=1
                // must be included exactly as any live row — the queries never filter on them.
                fun item(id: String, vault: String, rev: Int, deleted: Int = 0, conflict: Int = 0) =
                    c.exec(
                        """INSERT INTO items(itemId,vaultId,rev,createdAt,updatedAt,deleted,conflict,formatVersion,attachmentIds,blob,blobSize)
                           VALUES(?,?,?,0,0,?,?,1,'[]',?,0)""",
                        id, vault, rev, deleted, conflict, if (deleted == 1) null else "b",
                    )
                // vp: items straddling every `since` boundary below.
                item("p-r5", "vp", 5); item("p-r30", "vp", 30); item("p-r80", "vp", 80)
                item("p-tomb", "vp", 60, deleted = 1); item("p-conflict", "vp", 70, conflict = 1)
                // vs: OLD items (rev ≤ since) that only the BUMPED grant rev (50) can deliver —
                // the arm-2 case. Plus a NEW vs item to prove arm 1 still covers it.
                item("s-old3", "vs", 3); item("s-old10", "vs", 10, conflict = 1); item("s-new90", "vs", 90)
                // vr: revoked — must NEVER appear at any since, at any rev.
                item("r-r5", "vr", 5); item("r-r99", "vr", 99)
                // vo: not mine — must NEVER appear.
                item("o-r5", "vo", 5)
            }

            for (since in listOf(0L, 5L, 10L, 40L, 60L, 100L)) {
                val production = db.read { c ->
                    c.queryAll(PRODUCTION, "me", since, "me", since, since) { it.getString(1) }
                }.sorted()
                val oracle = db.read { c ->
                    c.queryAll(ORACLE, "me", since, since) { it.getString(1) }
                }.sorted()
                assertEquals(oracle, production, "UNION ALL pull diverged from the OR-join oracle at since=$since")
                // A revoked/foreign row must never leak, regardless of the equivalence.
                assertTrue(production.none { it.startsWith("r-") || it.startsWith("o-") }, "revoked/foreign item leaked at since=$since")
            }

            // Spot-pin the arm-2 semantics the equivalence rests on: at since=40, vs's OLD
            // items (rev 3 & 10 ≤ 40) arrive ONLY because grant rev 50 > 40; vp's rev-30 item
            // (grant rev 1 ≤ 40) does NOT. This is exactly the case a naive `i.rev>since` rewrite
            // would silently drop.
            val at40 = db.read { c -> c.queryAll(PRODUCTION, "me", 40L, "me", 40L, 40L) { it.getString(1) } }.toSet()
            assertTrue("s-old3" in at40 && "s-old10" in at40, "arm-2 grant-rev backfill dropped vs's old items")
            assertTrue("p-r30" !in at40, "an item under both rev bounds must not appear")
            assertTrue("p-r80" in at40, "arm-1 normal delta dropped a new item")
        }
    }
}
