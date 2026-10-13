package io.silencelen.andvari.server

import io.ktor.server.testing.testApplication
import io.silencelen.andvari.core.client.Account
import io.silencelen.andvari.core.client.AndvariApi
import io.silencelen.andvari.core.client.ApiException
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.core.model.TotpStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Security review 2026-10 follow-up (server F4, client half): the server now refuses a FIRST TOTP
 * enrollment from a session whose password login is older than the fresh-login window unless the
 * setup body carries `currentAuthKey`. The native clients (Android, desktop) enroll through core's
 * [AndvariApi.totpSetupWithPassword], which derives that key from the typed master password under
 * the account's own KDF salt/params — so enrolling keeps working long after sign-in. Driven through
 * the REAL Kotlin client stack against the in-process server, like ClientEngineTest.
 */
class TotpEnrollClientTest : P4TestSupport() {

    @Test
    fun nativeClient_enrollsFromAStaleSession_withThePassword() = testApplication {
        val services = buildServices(config(), Notifier())
        application { andvariModule(services) }
        val api = AndvariApi("", createClient { })
        val policy = api.clientPolicy()
        val password = "native enrol password one"
        val (req, account) = Account.enroll(
            inviteToken = bootstrapToken, email = "native@x.com", displayName = "N", password = password,
            params = policy.kdfParams, recoveryPublicKey = Bytes.fromB64(api.recoveryPubkey()),
            recoveryFingerprint = policy.recoveryFingerprint, deviceName = "native", crypto = crypto,
        )
        val s = api.register(req)
        services.repo.db.tx { c -> c.exec("UPDATE devices SET createdAt=? WHERE userId=?", now() - 3_600_000, s.userId) }

        // The bare call is what the server now refuses outside the window…
        val bare = assertFailsWith<ApiException> { api.totpSetup() }
        assertEquals("reauth_required", bare.code)
        // …a wrong password is refused, not silently ignored — since the A9 review (LOW-1) LOCALLY: the fenced derivation
        // proves the password against the session UVK before anything is derived for the server, so nothing is sent…
        assertFailsWith<io.silencelen.andvari.core.client.ReauthFailedException> { api.totpSetupWithPassword("not the password", account) }
        assertEquals(TotpStatus(enrolled = false, pendingSetup = false), api.totpStatus(), "no setup was staged by the refused attempt")
        // …and the client's password-carrying enrolment goes through.
        val setup = api.totpSetupWithPassword(password, account)
        assertTrue(setup.secretBase32.isNotEmpty())
        assertEquals(TotpStatus(enrolled = false, pendingSetup = true), api.totpStatus())
        api.totpConfirm(totpCode(setup.secretBase32))
        assertEquals(TotpStatus(enrolled = true, pendingSetup = false), api.totpStatus())
    }
}
