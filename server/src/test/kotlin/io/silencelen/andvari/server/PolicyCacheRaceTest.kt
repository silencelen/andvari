package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.ClientPolicy
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals

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

            val readerEntered = CountDownLatch(1)
            val readerSaw = AtomicLong(-1)
            val reader = thread(name = "policy-reader") {
                readerEntered.countDown()
                readerSaw.set(service.policy().autoLockSeconds.toLong())
            }
            readerEntered.await()
            // The reader is now inside the read-through: mid-decode if the publish is unguarded,
            // holding the Db lock if it is guarded. Either way the update below is the racer.
            Thread.sleep(50)
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
