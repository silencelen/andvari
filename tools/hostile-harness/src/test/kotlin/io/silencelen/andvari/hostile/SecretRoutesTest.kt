package io.silencelen.andvari.hostile

import io.silencelen.andvari.core.model.wire.Caller
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The bench's list of the routes that carry a value derived from an account's secrets ([World.SECRET_ROUTES]) is held to
 * the server's route table (spec 03 §0.2): a route the list misses is one the password rule's scenarios would never see a
 * leak on. Setting up two-step sign-in (row 14: a password proof and a code) and the operator's † routes were missing.
 */
class SecretRoutesTest {
    @Test fun everyRouteThatTakesAPasswordProofOrACodeIsASecretRoute() {
        val proofs = WireRoute.entries.filter { it.caller == Caller.SESSION_REAUTH || it.caller == Caller.OPERATOR_REAUTH }
        assertTrue(proofs.isNotEmpty())
        assertEquals(emptyList(), proofs.filter { it !in World.SECRET_ROUTES }, "a † route (a currentAuthKey in its body) missing from the list")
        for (r in listOf(WireRoute.PRELOGIN, WireRoute.LOGIN, WireRoute.TOTP_SETUP, WireRoute.TOTP_CONFIRM, WireRoute.TOTP_DISABLE,
            WireRoute.RECOVERY_SELF_VERIFY, WireRoute.RECOVERY_SELF_COMMIT, WireRoute.DEVICE_LINK_PICKUP, WireRoute.RECOVERY_REQUEST_COMMIT)) {
            assertTrue(r in World.SECRET_ROUTES, "$r carries an authKey, a recovery proof or a two-step code")
        }
        // Creating an account sends nothing of an existing one.
        assertTrue(WireRoute.REGISTER !in World.SECRET_ROUTES)
    }
}
