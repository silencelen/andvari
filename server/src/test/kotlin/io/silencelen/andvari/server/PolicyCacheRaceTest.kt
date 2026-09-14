package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.ClientPolicy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The policy read-through cache (quality-perf--7) vs a concurrent admin update — polish review
 * 2026-07-27 `parity--2`. The cache has no TTL, so a single lost race is PERMANENT: the server
 * would hand every client a stale ClientPolicy (min versions, KDF floor, quotas, autolock) until
 * the next restart. Both tests drive [Service] directly — the race lives under the routes.
 */
class PolicyCacheRaceTest : P4TestSupport() {

    /**
     * A stored policy whose DECODE is slow on purpose. The poisoning window is exactly "row read →
     * decode → publish"; a real policy decodes in microseconds, so a plain two-thread loop would be
     * a coin flip. [minVersion] is admin-settable and NOT stripped by setPolicy, so filling it makes
     * that window tens of milliseconds wide and the interleaving reliable in both directions:
     * the writer lands its whole tx inside the window, and with the fix in place the writer instead
     * queues on the Db lock the reader is holding.
     */
    private fun slowToDecode(autoLockSeconds: Int) = ClientPolicy(
        autoLockSeconds = autoLockSeconds,
        minVersion = (1..80_000).associate { "platform$it" to "1.$it.0" },
    )

    @Test
    fun concurrentSetPolicy_cannotPoisonTheCacheWithThePreWriteValue() {
        val cfg = config()
        Db(cfg.dbPath).use { db ->
            val service = Service(Repo(db), cfg)
            // Seed the slow row and leave the cache cold (setPolicy invalidates).
            service.setPolicy(slowToDecode(autoLockSeconds = 111))

            // H97: the interleaving is SIGNALLED, not slept for. The probe fires inside the
            // read-through once the stored row has been read and before the decoded value is
            // published — the exact poisoning window. The old `Thread.sleep(50)` only guessed the
            // reader had got that far; on a loaded host the writer could win the start instead,
            // and the witness assertion below then failed a correct server.
            val readerInWindow = CountDownLatch(1)
            service.policyReadThroughProbe = {
                // Signal ONLY. This runs holding the Db lock, so waiting for the writer here
                // would deadlock — the writer is meant to QUEUE on that lock, which is the
                // property under test.
                readerInWindow.countDown()
            }
            val readerSaw = AtomicLong(-1)
            val reader = thread(name = "policy-reader") {
                readerSaw.set(service.policy().autoLockSeconds.toLong())
            }
            assertTrue(readerInWindow.await(30, TimeUnit.SECONDS), "the reader never entered the read-through window")
            // The reader is now inside the read-through: mid-decode if the publish is unguarded,
            // holding the Db lock if it is guarded. Either way the update below is the racer.
            // The deliberately slow decode keeps that window tens of ms wide, so an unguarded
            // publish reliably loses the race and this test still fails if the guard is reverted.
            service.setPolicy(ClientPolicy(autoLockSeconds = 222))
            reader.join(30_000)

            // Witness that the interleaving actually happened — the reader's row read must have
            // preceded the update, or this test proves nothing.
            assertEquals(111L, readerSaw.get(), "the reader must have read the PRE-update policy")
            assertEquals(
                222, service.policy().autoLockSeconds,
                "a read that straddled the update must not publish its pre-write value into the cache",
            )
        }
    }

    /**
     * The read-through now takes the Db lock, and [Service.policy] is called from INSIDE the push tx
     * (the attachment quota) — which holds that same lock. Pins the reentrancy that keeps that from
     * deadlocking; a non-reentrant lock here would hang the whole push path, not fail a decode.
     */
    @Test
    fun policy_readThrough_isReentrantInsideAWriteTx() {
        val cfg = config()
        Db(cfg.dbPath).use { db ->
            val repo = Repo(db)
            val service = Service(repo, cfg)
            repo.setPolicyJson(json.encodeToString(ClientPolicy.serializer(), ClientPolicy(autoLockSeconds = 77)))
            val inTx = repo.db.tx { service.policy().autoLockSeconds }
            assertEquals(77, inTx, "a cold read-through must resolve inside an open tx")
        }
    }
}
