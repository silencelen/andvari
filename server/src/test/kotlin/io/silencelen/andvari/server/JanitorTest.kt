package io.silencelen.andvari.server

import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.model.Mutation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * F49 janitor retention sweep (design 2026-07-10 n2 §5 + amendments B1/B2/B3/A-fence):
 * per-table horizon prunes for all six tables, the `changes`+`oldestRetainedRev` fence
 * with its MAX(rev) floor (the B1 blocker pin — `currentRev` must never regress), the
 * 410 boundary (cursor at H−1 vs H), the spec 02 §7 invariant-(d) quiet-server
 * convergence, the accepted mutation-replay resurrection class, and dry-run inertness.
 * Rows are aged by writing old timestamps directly (or by sweeping with a future clock,
 * the VaultLifecycleTest idiom) — never by sleeping.
 */
class JanitorTest : P4TestSupport() {

    private fun Services.count(table: String): Long =
        repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM $table") { it.getLong(1) } ?: 0L }

    private fun Services.fence(): Long = repo.db.read { c -> repo.oldestRetainedRev(c) }

    // ---- per-table: one row past the horizon deleted, one inside kept (all six) ----

    @Test
    fun sweep_prunesEachTablePastHorizon_keepsInside() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "janitor prune password one", fast = true)
        client.register(owner, bootstrapToken)
        val item = owner.newItemId()
        client.push(owner, putMutation(owner, item, """{"name":"keep"}""", 0))
        val t = now()
        val deviceId = services.repo.db.read { c ->
            c.queryOne("SELECT deviceId FROM devices WHERE userId=?", owner.userId) { it.getString(1) }
        }!!

        // Age every changes row BELOW the newest (AUTOINCREMENT hands fresh inserts the top
        // revs, so aging is done by rewriting `at` in place, not by inserting old rows).
        val maxRev = services.repo.currentRevSafe()
        services.repo.db.tx { c -> c.exec("UPDATE changes SET at=? WHERE rev<?", t - 31 * Service.DAY_MS, maxRev) }

        services.repo.db.tx { c ->
            fun session(id: String, refreshExpiresAt: Long, revokedAt: Long?) = c.exec(
                """INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,refreshConsumedAt,createdAt,revokedAt)
                   VALUES(?,?,?,?,?,?,?,NULL,?,?)""",
                id, deviceId, owner.userId, uuid(), t, uuid(), refreshExpiresAt, t, revokedAt,
            )
            session("s-revoked-old", t + Service.DAY_MS, t - 91 * Service.DAY_MS) // out: revoked leg
            session("s-expired-old", t - 91 * Service.DAY_MS, null) // out: expiry leg (rotated-away, never revoked)
            session("s-revoked-new", t + Service.DAY_MS, t - Service.DAY_MS) // in: revoked, but inside 90d
            c.exec(
                "INSERT INTO mutations(deviceId,mutationId,resultJson,createdAt) VALUES(?,?,?,?)",
                deviceId, "m-old", "{}", t - 181 * Service.DAY_MS, // out; the real push row above stays in
            )
            c.exec("INSERT INTO audit(at,type) VALUES(?,?)", t - 366 * Service.DAY_MS, "old_event") // out; fresh rows stay
            c.exec(
                "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt,usedAt) VALUES(?,?,0,?,?,?)",
                "i-used-old", "a@x.com", t - 40 * Service.DAY_MS, t + Service.DAY_MS, t - 31 * Service.DAY_MS, // out: used leg
            )
            c.exec(
                "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt,usedAt) VALUES(?,?,0,?,?,NULL)",
                "i-expired-old", "b@x.com", t - 40 * Service.DAY_MS, t - 31 * Service.DAY_MS, // out: expiry leg
            )
            c.exec(
                "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt,usedAt) VALUES(?,?,0,?,?,NULL)",
                "i-live", "c@x.com", t, t + Service.DAY_MS, // in
            )
            c.exec("INSERT INTO hibp_cache(prefix,body,fetchedAt) VALUES('AAAAA','x',?)", t - 46 * Service.DAY_MS) // out
            c.exec("INSERT INTO hibp_cache(prefix,body,fetchedAt) VALUES('BBBBB','y',?)", t - Service.DAY_MS) // in
        }
        val changesBefore = services.count("changes")
        val mutationsBefore = services.count("mutations")
        val invitesBefore = services.count("invites")

        val res = services.janitor.sweep(t)

        assertFalse(res.dryRun)
        assertEquals(changesBefore - 1, res.prunedChanges)
        assertEquals(2L, res.prunedSessions)
        assertEquals(1L, res.prunedMutations)
        assertEquals(1L, res.prunedAudit)
        assertEquals(2L, res.prunedInvites)
        assertEquals(1L, res.prunedHibp)

        // Survivors: exactly the inside-horizon rows (and the live rows the flow created).
        assertEquals(1L, services.count("changes"))
        assertEquals(maxRev, services.repo.db.read { c -> c.queryOne("SELECT rev FROM changes") { it.getLong(1) } })
        assertEquals(maxRev, services.fence())
        val sessionIds = services.repo.db.read { c -> c.queryAll("SELECT sessionId FROM sessions") { it.getString(1) } }
        assertFalse("s-revoked-old" in sessionIds)
        assertFalse("s-expired-old" in sessionIds)
        assertTrue("s-revoked-new" in sessionIds)
        assertEquals(mutationsBefore - 1, services.count("mutations"))
        assertEquals(invitesBefore - 2, services.count("invites"))
        assertTrue(services.repo.db.read { c -> c.queryAll("SELECT tokenHash FROM invites") { it.getString(1) } }.contains("i-live"))
        assertEquals(0L, services.repo.db.read { c -> c.queryOne("SELECT COUNT(*) FROM audit WHERE type='old_event'") { it.getLong(1) } })
        assertEquals(
            listOf("BBBBB"),
            services.repo.db.read { c -> c.queryAll("SELECT prefix FROM hibp_cache") { it.getString(1) } },
        )
        // The registered device's LIVE session survived and the fence didn't over-advance:
        // an up-to-date cursor still syncs cleanly.
        val resp = client.sync(owner, maxRev)
        assertEquals(maxRev, resp.rev)
        assertTrue(resp.items.isEmpty() && resp.vaults.isEmpty() && resp.grants.isEmpty())
    }

    // ---- B1 blocker pin: idle server — the MAX(rev) row is NEVER deleted ----

    @Test
    fun changesFence_idleServer_retainsMaxRev_currentRevNeverRegresses() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "janitor idle password two", fast = true)
        client.register(owner, bootstrapToken)
        client.push(owner, putMutation(owner, owner.newItemId(), """{"name":"a"}""", 0))
        val maxRev = services.repo.currentRevSafe()
        val changesBefore = services.count("changes")

        // Sweep with a future clock: EVERY changes row is stale (the idle-server case).
        val res = services.janitor.sweep(now() + 31 * Service.DAY_MS)

        assertEquals(changesBefore - 1, res.prunedChanges)
        assertEquals(listOf(maxRev), services.repo.db.read { c -> c.queryAll("SELECT rev FROM changes") { it.getLong(1) } })
        assertEquals(maxRev, services.repo.currentRevSafe(), "currentRev must never regress")
        assertEquals(maxRev, services.fence())
        // An up-to-date cursor pulls a clean no-op — no 409 (rev unchanged), no 410.
        val resp = client.sync(owner, maxRev)
        assertEquals(maxRev, resp.rev)
        assertTrue(resp.items.isEmpty() && resp.vaults.isEmpty() && resp.grants.isEmpty() && resp.removedGrants.isEmpty())
        // Idempotent: a second sweep has nothing to prune and holds the fence.
        assertEquals(0L, services.janitor.sweep(now() + 31 * Service.DAY_MS).prunedChanges)
        assertEquals(maxRev, services.fence())
    }

    // ---- NOTE-8 boundary pin: cursor at H−1 → 410; cursor at H → serves ----

    @Test
    fun changesFence_boundaryPin_cursorBelowFence410s_atFenceServes() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "janitor bound password tre", fast = true)
        client.register(owner, bootstrapToken)
        client.push(owner, putMutation(owner, owner.newItemId(), """{"name":"a"}""", 0))
        client.push(owner, putMutation(owner, owner.newItemId(), """{"name":"b"}""", 0))
        val h = services.repo.currentRevSafe()
        assertTrue(h >= 2, "need H-1 > 0 so the since>0 gate applies")

        services.janitor.sweep(now() + 31 * Service.DAY_MS) // idle case: fence == H == MAX(rev)
        assertEquals(h, services.fence())

        val gone = client.get("/api/v1/sync?since=${h - 1}") { authed(owner) }
        assertEquals(HttpStatusCode.Gone, gone.status)
        assertEquals("resync_required", errorOf(gone))
        assertEquals(h, client.sync(owner, h).rev) // exactly AT the fence: serves normally
    }

    // ---- spec 02 §7 invariant (d): quiet-server convergence after a full sweep ----

    @Test
    fun quietServer_convergence_afterFullSweep() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "janitor quiet password for", fast = true)
        client.register(owner, bootstrapToken)
        val keep = owner.newItemId()
        val gone = owner.newItemId()
        client.push(owner, putMutation(owner, keep, """{"name":"keep"}""", 0))
        client.push(owner, putMutation(owner, gone, """{"name":"gone"}""", 0))
        val seen = client.sync(owner, 0)
        val staleCursor = seen.rev // a device that saw both items, then went offline
        client.push(owner, Mutation(uuid(), "delete", gone, owner.personalVaultId, seen.items.single { it.itemId == gone }.rev))
        val upToDate = client.sync(owner, staleCursor).rev

        // Idle past the fence, then ONE full sweep: tombstone purge + fence advance together.
        val res = services.janitor.sweep(now() + 31 * Service.DAY_MS)
        assertTrue(res.purgedItemTombstones.contains(gone))

        // (iii) currentRev never regressed; the fence sits exactly on it (idle case).
        assertEquals(upToDate, services.repo.currentRevSafe())
        assertEquals(upToDate, services.fence())
        // (i) the up-to-date cursor pulls a clean 200 no-op — no 409/410 loop.
        val noop = client.sync(owner, upToDate)
        assertEquals(upToDate, noop.rev)
        assertTrue(noop.items.isEmpty() && noop.vaults.isEmpty() && noop.grants.isEmpty())
        // (ii) the stale cursor 410s, and the mandated since=0 resync converges: the
        // deleted item is ABSENT (no resurrection), the live item present.
        val g = client.get("/api/v1/sync?since=$staleCursor") { authed(owner) }
        assertEquals(HttpStatusCode.Gone, g.status)
        assertEquals("resync_required", errorOf(g))
        val full = client.sync(owner, 0)
        assertEquals(upToDate, full.rev)
        assertTrue(full.items.any { it.itemId == keep })
        assertTrue(full.items.none { it.itemId == gone }, "deleted item stays deleted after resync")
    }

    // ---- accepted-class pin: >180d put replay after journal + tombstone prune ----

    @Test
    fun mutationReplay_afterJournalAndTombstonePrune_resurrectsAsCleanInsert() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "janitor replay password fem", fast = true)
        client.register(owner, bootstrapToken)
        val item = owner.newItemId()
        val put = putMutation(owner, item, """{"name":"lazarus"}""", 0) // ONE mutationId, replayed below
        val first = client.push(owner, put)
        assertEquals("applied", first.results.single().status)
        client.push(owner, Mutation(uuid(), "delete", item, owner.personalVaultId, first.results.single().newItemRev!!))

        // Age the journal past 180d and the tombstone past 30d directly, then sweep.
        services.repo.db.tx { c ->
            c.exec("UPDATE mutations SET createdAt=?", now() - 181 * Service.DAY_MS)
            c.exec("UPDATE items SET updatedAt=? WHERE itemId=?", now() - 31 * Service.DAY_MS, item)
        }
        val res = services.janitor.sweep(now())
        assertEquals(2L, res.prunedMutations) // the put row AND the delete row
        assertTrue(res.purgedItemTombstones.contains(item))
        assertEquals(0L, services.count("mutations"))

        // Replaying the SAME put mutationId now finds no journal row and no item row, so it
        // applies as a clean `applied` INSERT — the item silently resurrects. This is the
        // ACCEPTED residual class (design 2026-07-10 n2 folded notes; same class as the
        // offline-re-add note on Repo.purgeItem), pinned here so a behavior change is loud.
        val replay = client.push(owner, put)
        assertEquals("applied", replay.results.single().status)
        val resurrected = client.sync(owner, 0).items.single { it.itemId == item }
        assertFalse(resurrected.deleted)
    }

    // ---- dry-run: counts populated, nothing deleted, fence untouched ----

    @Test
    fun dryRun_countsEverything_deletesNothing_fenceUntouched() = testApplication {
        val services = buildServices(config(janitorDryRun = true), Notifier())
        application { andvariModule(services) }
        val client = jsonClient(this)
        val owner = VirtualClient("owner@x.com", "janitor dryrun password six", fast = true)
        client.register(owner, bootstrapToken)
        client.push(owner, putMutation(owner, owner.newItemId(), """{"name":"a"}""", 0))
        val t = now()
        val deviceId = services.repo.db.read { c ->
            c.queryOne("SELECT deviceId FROM devices WHERE userId=?", owner.userId) { it.getString(1) }
        }!!
        val maxRev = services.repo.currentRevSafe()
        services.repo.db.tx { c ->
            c.exec("UPDATE changes SET at=? WHERE rev<?", t - 31 * Service.DAY_MS, maxRev)
            c.exec(
                """INSERT INTO sessions(sessionId,deviceId,userId,accessHash,accessExpiresAt,refreshHash,refreshExpiresAt,refreshConsumedAt,createdAt,revokedAt)
                   VALUES(?,?,?,?,?,?,?,NULL,?,?)""",
                "s-revoked-old", deviceId, owner.userId, uuid(), t, uuid(), t + Service.DAY_MS, t, t - 91 * Service.DAY_MS,
            )
            c.exec(
                "INSERT INTO mutations(deviceId,mutationId,resultJson,createdAt) VALUES(?,?,?,?)",
                deviceId, "m-old", "{}", t - 181 * Service.DAY_MS,
            )
            c.exec("INSERT INTO audit(at,type) VALUES(?,?)", t - 366 * Service.DAY_MS, "old_event")
            c.exec(
                "INSERT INTO invites(tokenHash,email,isAdmin,createdAt,expiresAt,usedAt) VALUES(?,?,0,?,?,NULL)",
                "i-expired-old", "b@x.com", t - 40 * Service.DAY_MS, t - 31 * Service.DAY_MS,
            )
            c.exec("INSERT INTO hibp_cache(prefix,body,fetchedAt) VALUES('AAAAA','x',?)", t - 46 * Service.DAY_MS)
        }
        val before = listOf("changes", "sessions", "mutations", "audit", "invites", "hibp_cache")
            .associateWith { services.count(it) }
        assertEquals(0L, services.fence())

        val res = services.janitor.sweep(t)

        // Counts report what WOULD go...
        assertTrue(res.dryRun)
        assertEquals(before.getValue("changes") - 1, res.prunedChanges)
        assertEquals(1L, res.prunedSessions)
        assertEquals(1L, res.prunedMutations)
        assertEquals(1L, res.prunedAudit)
        assertEquals(1L, res.prunedInvites)
        assertEquals(1L, res.prunedHibp)
        // ...but nothing went, and the fence did NOT advance.
        for ((table, n) in before) assertEquals(n, services.count(table), "dry-run must not delete from $table")
        assertEquals(0L, services.fence())
        assertEquals(maxRev, services.repo.currentRevSafe())
        // Even the pre-fence cursor still serves (no 410 in dry-run — nothing was pruned).
        assertEquals(maxRev, client.sync(owner, maxRev - 1).rev)
    }
}
