package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.client.session.ForgetEarlier
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A session record that the platform's secure store holds and cannot read now (it answers "nothing" for it, as the
 * iPhone's Keychain does before the first unlock since boot): that record may be the very account an address is tied to,
 * so the forgetting of an earlier account is neither offered nor made, as where the kept session names that account.
 * Before, a server that served ANOTHER account under the address in that state led the person, by their own two
 * confirmations, to remove the kept account's address record, its identity record and its copy; once the platform read
 * the record again, it named an account whose records were gone.
 */
class EngineForgetEarlierUnreadableSessionTest {
    private val k = SweepSteps(createCryptoProvider())

    private fun addressRecord(w: SweepWorld) = w.state.inner.get(SessionKeeper.EMAIL_BINDING_PREFIX + w.home.origin + "|" + k.alice)

    /** What the kept account has on this device: its address record, its records kept by its id, its copy, its session record. */
    private fun kept(w: SweepWorld): List<Any?> = listOf(
        addressRecord(w), k.byId(w), w.state.inner.get(EngineAppApi.HELD_KEY), w.files.deleted.toList(), w.secure.inner.get(SessionKeeper.KEY),
    )

    /**
     * alice's account kept at h.example, locked; a start at which the platform cannot read its session record; h.example
     * then serves another account under her address, and her sign-in there meets the identity fault.
     */
    private suspend fun unreadableAndAnotherAccountServed(): Pair<SweepWorld, List<Any?>> {
        val w = k.world()
        w.u = k.register(w.app, "h.example", k.alice)
        w.app.lock()
        w.app.close()
        w.secure.handsNothingFor += SessionKeeper.KEY
        w.app = k.device(w)
        assertNull(w.app.keeper.session, "the platform hands nothing for the record")
        val before = kept(w)
        assertEquals(w.u, addressRecord(w)?.substringBefore('|'))
        assertTrue(k.byId(w).containsKey("ovh.identity|${w.u}"))
        w.home.accounts.remove(k.alice)
        assertNotEquals(w.u, k.register(k.otherDevice(w.home), "h.example", k.alice))
        assertEquals(SignInAnswer.IDENTITY_FAULT, k.signInAt(w.app, w.home.origin, k.alice))
        return w to before
    }

    @Test fun aSessionRecordThePlatformCannotReadNowStopsTheOfferOfTheForgetting() = runBlocking<Unit> {
        val (w, before) = unreadableAndAnotherAccountServed()
        assertNull(w.app.snapshot.earlierAccount, "no offer while the session record cannot be read")
        assertEquals(before, kept(w), "nothing of the kept account went")
    }

    @Test fun aSessionRecordThePlatformCannotReadNowStopsTheForgettingItselfAndTheAccountIsThereOnceItReadsAgain() = runBlocking<Unit> {
        val (w, before) = unreadableAndAnotherAccountServed()
        val r = w.app.forgetEarlier(w.home.origin, k.alice, k.alice, w.u)
        assertEquals(before, kept(w), "the address record, the identity record, the copy and the session record stay")
        assertEquals(ForgetEarlier.OpenForThatAccount, r, "refused, as where the kept session names the account")
        // The platform reads the record again: the account is there, locked, with everything it had.
        w.app.close()
        w.secure.handsNothingFor.clear()
        w.app = k.device(w)
        assertEquals(w.u, assertNotNull(w.app.keeper.session).userId)
        assertEquals(AppPhase.LOCKED, w.app.snapshot.phase)
        assertEquals(before, kept(w))
    }
}
