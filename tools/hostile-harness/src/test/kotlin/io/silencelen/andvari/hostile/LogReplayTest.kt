package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.e2e.accept
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.doc
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.log.AppendOutcome
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.log.VaultLogStatus
import io.silencelen.andvari.core.client.log.VerifiedVaultState
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.cutLogAt
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.fullSyncPage
import io.silencelen.andvari.hostile.proxy.remove
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.withVaultRowsFrom
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The vault log's answers replayed or reordered (design §3.7, §3.9; spec 03 §10.3): a log append's answer is a hint
 * the device checks by fetching, never the verified state itself; and a log page from before a removal or a role
 * change never shows a removed member as a member, or a reader as a writer, on a device that verified the change. The
 * verified state never goes back, and what the device shows is what the newest verified log says.
 */
class LogReplayTest {
    /** The verified state the device holds for [v], whatever mark it carries (withheld, failed, frozen). */
    private fun held(s: VaultLogStatus): VerifiedVaultState? = when (s) {
        is VaultLogStatus.Verified -> s.state
        is VaultLogStatus.Withheld -> s.state
        is VaultLogStatus.Frozen -> s.state
        is VaultLogStatus.Failed -> s.lastGood
        is VaultLogStatus.Removed -> s.state
        is VaultLogStatus.Purged -> s.state
        else -> null
    }

    private fun AccountSession.state(v: String): VerifiedVaultState = assertNotNull(held(logs.status(v)), "${logs.status(v)}")

    /**
     * Alice appends to a shared vault; the server answers with: an earlier append's answer, the append not stored (a
     * replay); another vault's append answer (stored); the right answer with the head of an earlier position; and,
     * for two appends to two vaults, each with the other's answer (reordered). A replay whose append was not stored
     * leaves the append pending and the verified state where it was, and the re-post lands it; every stored append is
     * the newest verified state; nothing goes back.
     */
    @Test fun aReplayedOrReorderedLogAppendAnswerNeverMovesTheVerifiedStateBack() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val bob = account(bh).userId
        a.ok(v, LogAction.Role(bob, "reader"))
        val earlier = assertNotNull(proxy.last(WireRoute.LOG_APPEND, "alice")?.upstream?.json)
        val w = a.ok(null, LogAction.Create("Other"))
        val other = assertNotNull(proxy.last(WireRoute.LOG_APPEND, "alice")?.upstream?.json)
        assertEquals(2L, a.state(v).headSeq)

        // A replay of an earlier answer; the append never reached the store.
        var rule = proxy.on(WireRoute.LOG_APPEND, "alice", times = 1) { _ -> Resp.json(200, earlier) }
        assertEquals(AppendOutcome.Pending, a.logs.append(v, LogAction.Role(bob, "writer")), "a replayed answer is not an append")
        rule.remove()
        assertEquals(2L, a.state(v).headSeq, "the replay moved nothing")
        assertEquals("reader", a.state(v).members[bob]?.role, "the device shows the newest verified log")
        a.logs.retryPending()
        assertEquals(3L, a.state(v).headSeq, "the re-post lands it")
        assertEquals("writer", a.state(v).members[bob]?.role)

        val lies = listOf<Pair<String, Handler>>(
            "another vault's append answer" to Handler { x -> x.forward().let { if (it.ok) Resp.json(200, other) else it } },
            "the right answer with an earlier head" to editAnswer { it.set("head", earlier.getValue("head")).set("rev", 1L) },
        )
        for ((i, lie) in lies.withIndex()) {
            rule = proxy.on(WireRoute.LOG_APPEND, "alice", times = 1, handler = lie.second)
            val role = if (i % 2 == 0) "reader" else "writer"
            val r = assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Role(bob, role)), lie.first)
            rule.remove()
            assertEquals(4L + i, r.state.headSeq, "${lie.first}: the stored append is the verified state")
            assertEquals(4L + i, a.state(v).headSeq, lie.first)
            assertEquals(role, a.state(v).members[bob]?.role, lie.first)
        }

        // Reordered: each of two appends, in two vaults, answered with the other's answer.
        val answers = HashMap<String, JsonObject>()
        rule = proxy.on(WireRoute.LOG_APPEND, "alice", times = 2) { x ->
            val real = x.forward()
            if (!real.ok) return@on real
            val mine = x.req.param("vaultId")!!
            answers[mine] = real.json!!
            Resp.json(200, (answers.entries.firstOrNull { it.key != mine }?.value ?: other))
        }
        val rv = assertIs<AppendOutcome.Appended>(a.logs.append(v, LogAction.Role(bob, "reader")))
        val rw = assertIs<AppendOutcome.Appended>(a.logs.append(w, LogAction.Add(bob, "reader")))
        rule.remove()
        assertEquals(6L, rv.state.headSeq)
        assertEquals(1L, rw.state.headSeq)
        assertEquals(6L, a.state(v).headSeq)
        assertEquals(1L, a.state(w).headSeq)
        assertEquals("reader", a.state(v).members[bob]?.role)
        assertTrue(bob in a.state(w).members)
        a.synced()
        assertEquals(6L, a.state(v).headSeq, "an honest sync agrees")
    }

    /**
     * Alice demotes Bob to reader and removes Carol; every device verifies it. The server then serves each of them the
     * vault's log as it was before (and, to Carol, her old grant and vault rows): Bob is still a reader on his device and
     * writes nothing, Carol is still removed on hers and writes nothing, Alice still shows neither change undone. The
     * older page is withholding (§3.9: "The server is showing an older version"), never the truth; the honest log then
     * clears the mark and shows the same.
     */
    @Test fun aLogPageReplayedFromBeforeARemovalOrARoleChangeNeverShowsTheOldMembership() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        val ch = member("carol")
        val v = sharedVault(ah, bh)
        val a = account(ah)
        val b = account(bh)
        val c = account(ch)
        connect(ah, ch, origin)
        a.ok(v, LogAction.Add(c.userId, "writer"))
        accept(c, v)
        assertEquals(null, a.putItem(v, doc("shared")).second)
        b.synced()
        c.synced()
        val before = a.state(v).headSeq
        assertTrue(b.writeAllowed(v) && c.writeAllowed(v), "both write before the change")
        // Carol's own rows of the vault while she was a member, as a server that keeps them can serve them again.
        var captured: JsonObject? = null
        val capture = proxy.on(WireRoute.SYNC, "carol", times = 1) { x -> x.forward().also { captured = x.fullSyncPage() } }
        c.sync()
        capture.remove()
        val carolsRows = assertNotNull(captured, "Carol's rows while she was a member")

        a.ok(v, LogAction.Role(b.userId, "reader"))
        a.ok(v, LogAction.Remove(c.userId))
        val after = a.state(v)
        for (s in listOf(a, b, c)) s.sync()
        b.logs.refresh(v, null, null, force = true)
        c.logs.refresh(v, null, null, force = true)
        assertEquals("reader", b.state(v).members[b.userId]?.role)
        assertFalse(c.userId in c.state(v).members, "Carol verified her removal")
        assertFalse(b.writeAllowed(v) || c.writeAllowed(v))
        val shown = listOf(a, b, c).associateWith { s -> s.items(v) }

        for ((tag, s) in listOf("alice" to a, "bob" to b, "carol" to c)) {
            val rules = proxy.cutLogAt(tag, v, before).toMutableList()
            if (tag == "carol") rules += proxy.on(WireRoute.SYNC, "carol") { x ->
                x.forward().let { r -> if (r.ok) r.withJson { it.withVaultRowsFrom(carolsRows, v, items = true) } else r }
            }
            s.sync()
            s.logs.refresh(v, null, null, force = true)
            val status = s.logs.status(v)
            val kept = s.state(v)
            assertTrue(kept.headSeq >= after.headSeq, "$tag: the verified state never goes back ($status)")
            assertEquals("reader", kept.members[b.userId]?.role, "$tag: Bob is still a reader ($status)")
            assertFalse(c.userId in kept.members, "$tag: Carol is still removed ($status)")
            if (s !== a) assertFalse(s.writeAllowed(v), "$tag: no write is allowed")
            // Withholding, or (for Carol) still the removal she verified; never a state at the older page's head.
            assertTrue(status is VaultLogStatus.Withheld || status is VaultLogStatus.Removed || status is VaultLogStatus.Verified,
                "$tag: an older page is withholding, never the truth: $status")
            assertEquals(shown[s], s.items(v), "$tag: the device shows what it showed")
            rules.remove()
            s.sync()
            s.logs.refresh(v, null, null, force = true)
            val honest = s.logs.status(v)
            assertTrue(honest is VaultLogStatus.Verified || (s === c && honest is VaultLogStatus.Removed), "$tag: the honest log clears the mark: $honest")
            assertEquals(after.headSeq, s.state(v).headSeq, tag)
        }
        assertTrue(a.writeAllowed(v), "the owner writes again")
    }
}
