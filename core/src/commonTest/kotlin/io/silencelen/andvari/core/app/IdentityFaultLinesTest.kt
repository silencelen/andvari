package io.silencelen.andvari.core.app

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Every result that is the identity fault a sign-in has carries that fault's own line, so that no app words it: a
 * sign-in, a kit's check and a new account's making, as the device link's password step and a recovery's commit already
 * did. (Before, the first three carried no sentence, and the apps said lines of their own that were not so where the same
 * account is served under another key.)
 */
class IdentityFaultLinesTest {
    @Test fun theIdentityFaultsResultsCarryItsOwnLine() {
        val results: List<IntentResult> = listOf(
            SignInAnswer.IDENTITY_FAULT, KitRecoverResult.IDENTITY_FAULT, CreateAccountResult.IDENTITY_FAULT,
            LinkPasswordResult.IDENTITY_FAULT, ReplacePasswordResult.IDENTITY_FAULT,
        )
        for (r in results) assertEquals(CopyKey.IDENTITY_FAULT_ADDRESS_KNOWN, r.sentence, "$r of ${r::class.simpleName}")
    }
}
