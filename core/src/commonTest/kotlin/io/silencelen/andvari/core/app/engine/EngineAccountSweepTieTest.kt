package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.ForgetEarlierResult
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.client.pin.PinStore
import io.silencelen.andvari.core.client.session.SessionKeeper
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Where something ends, the records kept by the account's id stay while the account is known by the sweep's own rule apart
 * from what that end removes, read before anything is removed: the tie of an end and the sweep agree. The state, built by
 * hand: the same account served at h.example and other.example, a copy of it held at both, and at other.example neither an
 * address record nor a device's row (nothing there that the tie between servers reads). The copy held at other.example
 * makes the account known. Before, a deletion at h.example, "Forget this server" for h.example and the forgetting of the
 * account as an earlier one at h.example each removed its identity record and everything kept by its id.
 */
class EngineAccountSweepTieTest {
    private val k = SweepSteps(createCryptoProvider())

    private suspend fun heldAtTheOtherServerToo(): Pair<SweepWorld, Set<String>> {
        val w = k.world(sameInstance = true)
        w.u = k.register(w.app, "h.example", k.alice)
        w.other.accounts[k.alice] = assertNotNull(w.home.accounts[k.alice])
        k.loseSession(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.other.origin, k.alice))
        k.loseSession(w)
        assertEquals(SignInAnswer.DONE, k.signInAt(w.app, w.home.origin, k.alice))
        for (key in w.state.inner.keys().filter { it.startsWith(SessionKeeper.EMAIL_BINDING_PREFIX + w.other.origin) || it.startsWith("ovh.dev|${w.other.origin}") })
            w.state.inner.set(key, null)
        assertTrue(heldThere(w), "a copy is held at other.example")
        assertFalse(PinStore.tiedElsewhere(w.state, w.u, w.home.origin), "nothing there that the tie reads")
        val before = k.byId(w).keys
        assertTrue("ovh.identity|${w.u}" in before)
        return w to before
    }

    private fun heldThere(w: SweepWorld) = w.state.inner.get(EngineAppApi.HELD_KEY).orEmpty().split('\n').contains("${w.other.origin}|${w.u}")

    private fun keptAll(w: SweepWorld, before: Set<String>, label: String) {
        assertTrue(heldThere(w), "$label: the copy at other.example is still held")
        assertEquals(before, k.byId(w).keys, "$label: the identity record and everything kept by the id stay")
        k.restart(w)
        assertEquals(before, k.byId(w).keys, "$label: and through the next start")
    }

    @Test fun aDeletionAtOneServerKeepsWhatIsKeptByTheIdOfAnAccountWhoseCopyIsHeldAtAnother() = runBlocking<Unit> {
        val (w, before) = heldAtTheOtherServerToo()
        k.deleteAt(w, w.home)
        keptAll(w, before, "the deletion at h.example")
    }

    @Test fun forgettingOneServerKeepsWhatIsKeptByTheIdOfAnAccountWhoseCopyIsHeldAtAnother() = runBlocking<Unit> {
        val (w, before) = heldAtTheOtherServerToo()
        assertEquals(PlainResult.DONE, w.app.instance.forgetServer(assertNotNull(w.app.snapshot.instance)))
        keptAll(w, before, "h.example forgotten")
    }

    @Test fun forgettingTheEarlierAccountAtOneServerKeepsWhatIsKeptByTheIdOfAnAccountWhoseCopyIsHeldAtAnother() = runBlocking<Unit> {
        val (w, before) = heldAtTheOtherServerToo()
        k.loseSession(w)
        w.home.accounts.remove(k.alice)
        assertNotEquals(w.u, k.register(k.otherDevice(w.home), "h.example", k.alice))
        assertEquals(SignInAnswer.IDENTITY_FAULT, k.signInAt(w.app, w.home.origin, k.alice))
        assertEquals(ForgetEarlierResult.FORGOTTEN, k.forgetEarlier(w))
        keptAll(w, before, "the earlier account forgotten at h.example")
    }
}
