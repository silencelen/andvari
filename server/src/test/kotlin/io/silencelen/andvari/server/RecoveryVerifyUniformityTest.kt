package io.silencelen.andvari.server

import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.RecoveryVerifyRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

/**
 * Security review 2026-10 (server F3): /recovery/self/verify claimed timing-identical failure
 * branches, but only "active account with a recovery row, wrong secret" wrote an audit row — an
 * fsync'd SQLite commit in its own tx. Unknown email, a non-active account and an account with no
 * row ran only the dummy argon2id. Every account gets a mandatory recovery row at register, so the
 * extra commit marked exactly the addresses that hold accounts: an enumeration oracle around the
 * fake-salt / dummy-verifier design. Login closed the same gap by auditing unknown addresses (F20).
 *
 * Now every failure branch writes ONE recovery_self_verify_fail row through the same call: an
 * anonymous one (no userId, no email — naming it would make the row itself the oracle, INFO-1)
 * for an unknown address, an attributed one otherwise.
 */
class RecoveryVerifyUniformityTest : P4TestSupport() {

    private val ip = "test"
    private val junkKey = Bytes.toB64(ByteArray(32) { 5 })

    private fun failRows(services: Services) = services.repo.auditQuery(0, "recovery_self_verify_fail", null, 50)

    @Test
    fun unknownEmail_writesTheSameAnonymousFailRow() {
        val services = buildServices(config(), Notifier())
        assertFailsWith<Unauthorized> {
            services.service.recoverySelfVerify(RecoveryVerifyRequest("nobody@x.com", junkKey), ip)
        }
        val row = failRows(services).single()
        assertNull(row.userId, "an unknown address must stay anonymous")
        assertNull(row.meta, "the submitted email must never reach the audit log")
    }

    @Test
    fun activeAccountWithoutARecoveryRow_writesAFailRow() {
        val services = buildServices(config(), Notifier())
        val vc = VirtualClient("norow@x.com", "no recovery row password")
        val s = services.service.register(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), ip)
        services.repo.db.tx { c -> c.exec("DELETE FROM member_recovery WHERE userId=?", s.userId) }
        assertFailsWith<Unauthorized> {
            services.service.recoverySelfVerify(RecoveryVerifyRequest(vc.email, junkKey), ip)
        }
        assertEquals(1, failRows(services).size)
    }

    @Test
    fun disabledAccount_writesAFailRow() {
        val services = buildServices(config(), Notifier())
        val vc = VirtualClient("disabled@x.com", "disabled account password")
        val s = services.service.register(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), ip)
        services.repo.db.tx { c -> c.exec("UPDATE users SET status='disabled' WHERE userId=?", s.userId) }
        assertFailsWith<Unauthorized> {
            services.service.recoverySelfVerify(RecoveryVerifyRequest(vc.email, junkKey), ip)
        }
        assertEquals(1, failRows(services).size)
    }

    @Test
    fun wrongSecretOnARealAccount_stillWritesExactlyOneRow() {
        val services = buildServices(config(), Notifier())
        val vc = VirtualClient("real@x.com", "real account password")
        services.service.register(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), ip)
        assertFailsWith<Unauthorized> {
            services.service.recoverySelfVerify(RecoveryVerifyRequest(vc.email, junkKey), ip)
        }
        assertEquals(1, failRows(services).size)
    }
}
