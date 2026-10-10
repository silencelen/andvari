package io.silencelen.andvari.server

import io.silencelen.andvari.core.model.DeviceInfo
import io.silencelen.andvari.core.model.LoginRequest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull

/**
 * Security review 2026-10 (server F5): login verified the password outside any lock and then
 * opened a SEPARATE write tx to mint the session, without re-checking that the verifier it had
 * just matched was still the account's. A password change, a self-recovery commit or an admin
 * recovery replaces the verifier and revokes every session in one tx — and a login that passed
 * Argon2 against the OLD verifier just before that commit then minted a fresh, unrevoked session
 * just after it. The remediation the member ran to lock an attacker out let the attacker back in.
 *
 * Driven through [Service.loginPreMintProbe], which runs in exactly that window.
 */
class LoginRevocationRaceTest : P4TestSupport() {

    private val ip = "test"

    private fun enrolled(): Pair<Services, VirtualClient> {
        val services = buildServices(config(), Notifier())
        val vc = VirtualClient("race@x.com", "the old password, phished")
        val s = services.service.register(vc.buildRegister(bootstrapToken, recovery.publicKey, fingerprint), ip)
        vc.userId = s.userId; vc.accessToken = s.accessToken; vc.refreshToken = s.refreshToken
        return services to vc
    }

    private fun liveSessions(services: Services, userId: String): Int = services.repo.db.read { c ->
        c.queryOne("SELECT COUNT(*) FROM sessions WHERE userId=? AND revokedAt IS NULL", userId) { it.getInt(1) } ?: 0
    }

    @Test
    fun passwordChangeCommittingMidLogin_leavesTheOldPasswordLoginWithNoSession() {
        val (services, victim) = enrolled()
        val victimPrincipal = assertNotNull(services.service.authenticate(victim.accessToken))
        services.service.loginPreMintProbe = {
            services.service.loginPreMintProbe = null
            // The member changes their password while the attacker's login is between verify and mint.
            services.service.changePassword(victimPrincipal, victim.buildPasswordChange("the new password, private"), ip)
        }

        assertFailsWith<Unauthorized> {
            services.service.login(LoginRequest(victim.email, victim.authKey, DeviceInfo("test", "attacker")), ip)
        }
        // Only the member's own session (kept by the password change) is live.
        assertEquals(1, liveSessions(services, victim.userId))
    }

    @Test
    fun accountDisabledMidLogin_mintsNoSession() {
        val (services, victim) = enrolled()
        services.service.loginPreMintProbe = {
            services.service.loginPreMintProbe = null
            services.repo.db.tx { c ->
                c.exec("UPDATE users SET status='disabled' WHERE userId=?", victim.userId)
                c.exec("UPDATE sessions SET revokedAt=? WHERE userId=? AND revokedAt IS NULL", now(), victim.userId)
            }
        }
        assertFailsWith<Unauthorized> {
            services.service.login(LoginRequest(victim.email, victim.authKey, DeviceInfo("test", "attacker")), ip)
        }
        assertEquals(0, liveSessions(services, victim.userId))
    }

    @Test
    fun anUncontendedLogin_stillMints() {
        val (services, victim) = enrolled()
        val s = services.service.login(LoginRequest(victim.email, victim.authKey, DeviceInfo("test", "phone")), ip)
        assertNotNull(services.service.authenticate(s.accessToken))
    }
}
