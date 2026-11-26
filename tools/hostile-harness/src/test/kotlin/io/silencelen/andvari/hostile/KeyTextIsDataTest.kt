package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.AccountSession
import io.silencelen.andvari.cli.Host
import io.silencelen.andvari.cli.SyncOutcome
import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.cli.e2e.connect
import io.silencelen.andvari.cli.e2e.ok
import io.silencelen.andvari.cli.e2e.synced
import io.silencelen.andvari.core.client.AttachmentRef
import io.silencelen.andvari.core.client.ItemDoc
import io.silencelen.andvari.core.client.items.ItemResult
import io.silencelen.andvari.core.client.items.NewAttachment
import io.silencelen.andvari.core.client.log.Adoption
import io.silencelen.andvari.core.client.log.LogAction
import io.silencelen.andvari.core.client.onboard.KeyEscapeException
import io.silencelen.andvari.core.client.onboard.SignIn
import io.silencelen.andvari.core.client.pin.FirstPin
import io.silencelen.andvari.core.client.pin.TrustGateWording
import io.silencelen.andvari.core.crypto.Bytes
import io.silencelen.andvari.tripwire.ZeroKeyTripwire
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Data that equals a vault's key is data. Every member of a shared vault holds its key, so its
 * owner can name the vault with the key's own text, and a writer can store an item or a file equal to it. Before the
 * fix, the guard's check of a lend's answer refused that name at every sync, every redraw and every unlock of every
 * other member's device (`KeyEscapeException`), and one hostile share stopped a person's app. The check is a development
 * net and runs only where the test machinery is on (spec 01 §8 rule 1, corrected); here a shipped build is played with
 * [ZeroKeyTripwire.asShipped], on the real server, two real accounts and the real item engine.
 */
class KeyTextIsDataTest {
    /** The text forms the check knew: hex (64 characters), base64url without padding (43), base64 with it (44). */
    private fun forms(vk: ByteArray): List<String> = listOf(
        Bytes.toHexLower(vk),
        java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(vk),
        java.util.Base64.getEncoder().encodeToString(vk),
    )

    private suspend fun AccountSession.saveFile(vaultId: String, name: String, data: ByteArray) {
        val ref = AttachmentRef(Bytes.uuidV4FromBytes(host.crypto.randomBytes(16)), "$name.bin", data.size.toLong(), Bytes.toB64(host.crypto.randomBytes(32)))
        val r = items.save(null, ItemDoc(type = "note", name = name, attachments = listOf(ref)), vaultId, uploads = listOf(NewAttachment(ref, data.copyOf())))
        assertIs<ItemResult.Ok<*>>(r, "save $name with a file: $r")
    }

    private suspend fun AccountSession.rename(vaultId: String, name: String) {
        val r = items.renameVault(vaultId, name)
        assertIs<ItemResult.Ok<*>>(r, "the owner renames the vault to $name: $r")
    }

    private suspend fun AccountSession.saveNote(vaultId: String, name: String, notes: String) {
        val r = items.save(null, ItemDoc(type = "note", name = name, notes = notes), vaultId)
        assertIs<ItemResult.Ok<*>>(r, "save $name: $r")
    }

    /** Everything Bob reads of the vault: its name, the notes, and the file, which opens to the key's bytes. */
    private suspend fun AccountSession.readsAll(v: String, name: String, vk: ByteArray, what: String) {
        assertEquals(name, vaultName(v), "$what: the vault is listed under the name its owner gave it")
        val all = items.items().filter { it.vaultId == v }
        for (f in forms(vk)) assertTrue(all.any { it.doc.notes == f }, "$what: the note holding $f is shown")
        val ref = all.single { it.doc.name == "the key as a file" }.doc.attachments.single()
        assertContentEquals(vk, assertIs<ItemResult.Ok<ByteArray>>(items.downloadAttachment(ref), what).value, "$what: the file opens")
    }

    /** The lock: [h]'s keys are wiped. The unlock: the same device signs in again and rebuilds from its own cache. */
    private suspend fun World.lockAndUnlock(h: Host, email: String): Pair<Host, AccountSession> {
        account(h).held.session.account.wipe()
        val next = Host(h.state, h.secure, server::now, http = server.httpFor(proxy.dial(tag(h))), deviceName = h.deviceName)
        var signIn = next.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        if (signIn is SignIn.TrustGateFirst) {
            // A device pinned through an enrol link signs in with its password only after the Trust Gate (design §8.5).
            val wording = if (next.trust.pinState(origin) is io.silencelen.andvari.core.client.pin.PinState.Pinned) TrustGateWording.LINK_OFFER_SIGN_IN else TrustGateWording.TYPED_ADDRESS
            val gate = assertIs<FirstPin.NeedsTrustGate>(next.trust.beginTrustGate(origin, wording), "the Trust Gate")
            assertIs<FirstPin.Pinned>(next.trust.confirmTrustGate(gate.confirm))
            signIn = next.onboarding(origin).signIn(email, Steps.PASSWORD.toCharArray())
        }
        assertIs<SignIn.SignedIn>(signIn, "the unlock")
        return next to assertNotNull(next.account(origin))
    }

    /**
     * The attack's sequence, with the name arriving from the other account. Alice names the vault with its key's text
     * before she shares it, so Bob is asked to accept it under that name; then she renames it to each text form in turn,
     * and stores notes holding each form and a file whose bytes are the key. Bob's device syncs, lists, reads and opens
     * them like any other, before and after a lock and an unlock; so does Alice's own.
     */
    @Test fun aVaultAnItemAndAFileEqualToTheVaultsKeyAreReadLikeAnyOtherAsShipped() = world {
        ZeroKeyTripwire.asShipped {
            operator()
            val ah = member("alice")
            val bh = member("bob")
            connect(ah, bh, origin)
            val a = account(ah)
            var b = account(bh)
            a.synced()
            val v = a.ok(null, LogAction.Create("Family"))
            val vk = assertNotNull(a.logs.keyFor(v))
            val first = forms(vk).first()
            a.synced()
            a.rename(v, first)
            a.ok(v, LogAction.Add(b.userId, "writer"))
            b.synced()
            val ask = assertIs<Adoption.AskAccept>(b.logs.adoption(v), "Bob is asked to accept the vault")
            assertEquals(first, ask.vaultName, "under the name its owner gave it")
            assertIs<Adoption.Adopted>(b.logs.answerIncoming(ask, accept = true))

            a.synced()
            for ((i, f) in forms(vk).withIndex()) a.saveNote(v, "note $i", f)
            a.saveFile(v, "the key as a file", vk)
            for (f in forms(vk)) {
                a.rename(v, f)
                assertEquals(f, a.vaultName(v), "the owner's own device lists it")
                assertIs<SyncOutcome.Synced>(b.sync(), "Bob's sync with the vault named $f")
                b.readsAll(v, f, vk, "named $f")
            }
            val last = forms(vk).last()
            b = lockAndUnlock(bh, "bob@example.org").second
            // The command-line host rebuilds from its cache (the decryption of every cached row) at its first sync.
            assertIs<SyncOutcome.Synced>(b.sync(), "Bob's first sync after the unlock")
            b.readsAll(v, last, vk, "after the lock and the unlock")
            val (_, a2) = lockAndUnlock(ah, "alice@example.org")
            assertIs<SyncOutcome.Synced>(a2.sync(), "Alice's first sync after her unlock")
            a2.readsAll(v, last, vk, "on the owner's device after her unlock")
        }
    }

    /**
     * Where the test machinery is on (every test unless it asks otherwise), the net against programming slips is still
     * there: the same name makes the lend that decrypts it refuse, which is what a shipped build did before the fix and
     * the reason a test of hostile data must ask for "as shipped".
     */
    @Test fun checkedTheSameNameStillTripsTheDevelopmentNet() = world {
        operator()
        val ah = member("alice")
        val bh = member("bob")
        connect(ah, bh, origin)
        val a = account(ah)
        val b = account(bh)
        a.synced()
        val v = a.ok(null, LogAction.Create("Family"))
        a.ok(v, LogAction.Add(b.userId, "writer"))
        b.synced()
        assertIs<Adoption.Adopted>(b.logs.answerIncoming(assertIs<Adoption.AskAccept>(b.logs.adoption(v)), accept = true))
        val vk = assertNotNull(a.logs.keyFor(v))
        a.synced()
        ZeroKeyTripwire.asShipped { a.rename(v, forms(vk).first()) }
        assertFailsWith<KeyEscapeException>("checked, the name equal to the key's text is refused at Bob's sync") { b.sync() }
    }
}
