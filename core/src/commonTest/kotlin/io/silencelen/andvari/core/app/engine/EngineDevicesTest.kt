package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.HowDeviceJoined
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PlainResult
import io.silencelen.andvari.core.app.ProofResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.Device
import io.silencelen.andvari.core.model.wire.WireError
import io.silencelen.andvari.core.model.wire.WireErrors
import io.silencelen.andvari.core.model.wire.WireJson
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** "Your devices" (§8.6) and "New devices must be linked" (§8.7) on the engine, and the "made on" line they name. */
class EngineDevicesTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val other = "22222222-2222-4222-8222-222222222222"

    private fun app(server: FakeInstance): EngineAppApi = EngineAppApi(
        AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to server)), MemoryDeviceState(), MemoryDeviceState(), crypto,
            { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
    ).also {
        it.linksFlow.answersPollMs = Long.MAX_VALUE
        it.start()
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun open(a: EngineAppApi) {
        a.entry.openOwnServer(a.at())
        assertEquals(ServerResult.DONE, a.entry.submitServerAddress(a.at(), "h.example"))
        assertEquals(ServerResult.DONE, a.entry.confirmTrustGate(a.at()))
        assertEquals(ServerResult.DONE, a.entry.createAccountHere(a.at()))
        assertEquals(SignUpStartResult.DONE, a.entry.startSignUp(a.at(), "alice@example.com", true))
        assertEquals(CodeResult.DONE, a.entry.verifySignUpCode(a.at(), "482915"))
        assertEquals(CreateAccountResult.DONE, a.entry.createAccount(a.at(), NewAccountInput("", "Alice", strong, true)))
        val kit = a.at<EntryScreen.Kit>()
        val doc = assertNotNull(a.kit.kitDocument(kit.kit))
        a.kit.proceedToConfirm(kit.kit)
        val confirm = a.at<EntryScreen.Kit>().kit
        assertEquals(KitConfirmResult.DONE, a.kit.confirmKit(confirm, confirm.groupsToType.map { doc.groups[it - 1] }))
        assertEquals(AppPhase.UNLOCKED, a.snapshot.phase)
    }

    @Test fun theDevicesAreListedAnotherIsRevokedAndRequireLinkIsSetBehindThePassword() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        open(a)
        server.accounts.values.single().devices[other] = "secret"
        assertNull(a.snapshot.account!!.devices, "closed until opened")
        assertEquals(PlainResult.DONE, a.devices.openDevices())
        val screen = assertNotNull(a.snapshot.account!!.devices)
        assertEquals(2, screen.devices.size)
        assertTrue(screen.devices.all { it.platform == AppPlatform.ANDROID && it.how == HowDeviceJoined.REGISTERED && it.live })
        assertFalse(screen.requireLinkKnown, "the server serves no read of the setting")

        val row = screen.devices.single { it.deviceId == other }
        val before = server.calls.count { it == WireRoute.DEVICE_REVOKE }
        assertEquals(ProofResult.WRONG_PASSWORD, a.devices.revokeDevice(row, ""), "an empty password sends nothing")
        assertEquals(before, server.calls.count { it == WireRoute.DEVICE_REVOKE })
        assertEquals(ProofResult.WRONG_PASSWORD, a.devices.revokeDevice(row, "not the password at all"))
        assertTrue(other in server.accounts.values.single().devices)
        assertEquals(ProofResult.DONE, a.devices.revokeDevice(a.snapshot.account!!.devices!!.devices.single { it.deviceId == other }, strong))
        assertTrue(other !in server.accounts.values.single().devices)
        assertTrue(a.snapshot.account!!.devices!!.devices.none { it.deviceId == other }, "the list was read again")
        assertEquals(ProofResult.STALE, a.devices.revokeDevice(row, strong), "a row no longer on show")

        assertEquals(ProofResult.DONE, a.devices.setRequireLink(true, strong))
        assertTrue(server.accounts.values.single().requireLink)
        val set = a.snapshot.account!!.devices!!
        assertTrue(set.requireLinkKnown && set.requireLink)

        // A lock closes the screen; what this device set is still known when it opens again.
        a.lock()
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertNull(a.snapshot.account!!.devices)
        assertEquals(PlainResult.DONE, a.devices.openDevices())
        assertTrue(a.snapshot.account!!.devices!!.requireLink)
        a.devices.closeDevices()
        assertNull(a.snapshot.account!!.devices)
    }

    /** The account's device list as a server serves it: this device ([here], the session's own), and [other] linked from it and no longer live. */
    private fun serve(server: FakeInstance, here: String, otherName: String = "Old laptop") {
        val list = listOf(
            Device(here, "android", "This Pixel", "0.30.0", 1_000, 9_000, live = true, how = "registered", current = true),
            Device(other, "macos", otherName, "0.29.1", 2_000, 5_000, live = false, how = "linked", linkedFrom = here),
        )
        server.override[WireRoute.DEVICES] = WireResult.Ok(WireJson.json.encodeToString(ListSerializer(Device.serializer()), list), 200)
    }

    /**
     * §8.7: a device that signed out or sat idle is not live, yet it is still a known device until a revoke clears its
     * secret, so it is revoked like any other; only this device is refused, and nothing is sent for it. The server's own
     * codes for a device that is not the account's (spec 03 §16.7) are NOT_POSSIBLE.
     */
    @Test fun aDeviceThatIsNotLiveIsStillRevokedAndOnlyThisOneIsRefused() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        open(a)
        server.accounts.values.single().devices[other] = "secret"
        serve(server, a.keeper.session!!.deviceId)
        assertEquals(PlainResult.DONE, a.devices.openDevices())
        val screen = assertNotNull(a.snapshot.account!!.devices)
        val (mine, old) = screen.devices
        assertTrue(mine.current && mine.name == "This Pixel" && mine.how == HowDeviceJoined.REGISTERED && mine.lastSeenAtMs == 9_000L)
        assertEquals(AppPlatform.MACOS, old.platform)
        assertEquals(HowDeviceJoined.LINKED, old.how)
        assertEquals("This Pixel", old.linkedFrom)
        assertFalse(old.live)

        val sent = server.calls.size
        assertEquals(ProofResult.NOT_POSSIBLE, a.devices.revokeDevice(mine, strong), "this device signs out instead")
        assertEquals(sent, server.calls.size, "nothing was sent for it")
        assertEquals(ProofResult.DONE, a.devices.revokeDevice(old, strong), "not live, still known: revoked")
        assertTrue(other !in server.accounts.values.single().devices)

        server.override[WireRoute.DEVICE_REVOKE] = WireResult.Refused(404, WireError(WireErrors.NO_SUCH_DEVICE, "m"))
        val again = a.snapshot.account!!.devices!!.devices.single { it.deviceId == other }
        assertEquals(ProofResult.NOT_POSSIBLE, a.devices.revokeDevice(again, strong))
        server.override[WireRoute.DEVICE_REVOKE] = WireResult.Refused(400, WireError(WireErrors.CANNOT_TARGET_SELF, "m"))
        assertEquals(ProofResult.NOT_POSSIBLE, a.devices.revokeDevice(a.snapshot.account!!.devices!!.devices.single { it.deviceId == other }, strong))
    }

    /**
     * Hostile-server finding D1: another account's WHOLE devices list (it marks that account's device `current`, never this
     * one) served as this account's. The session's device id now goes with the read, so the list is refused and
     * nothing of it is shown or named; this account's own list is shown again once it is served.
     */
    @Test fun anotherAccountsWholeDevicesListIsNeverShownAsThisAccountsOwn() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        open(a)
        serve(server, "44444444-4444-4444-8444-444444444444", otherName = "Bob's laptop")
        assertEquals(PlainResult.FAILED, a.devices.openDevices())
        assertNull(a.snapshot.account!!.devices, "nothing of Bob's list is on show")
        serve(server, a.keeper.session!!.deviceId)
        assertEquals(PlainResult.DONE, a.devices.openDevices())
        assertTrue(assertNotNull(a.snapshot.account!!.devices).devices.first().current)
    }

    /** A contact made on another device of the account names that device, from the device list. */
    @Test fun aContactMadeOnAnotherDeviceNamesThatDevice() = runBlocking<Unit> {
        val server = FakeInstance(crypto)
        val a = app(server)
        open(a)
        serve(server, a.keeper.session!!.deviceId, otherName = "Work laptop")
        val carol = "33333333-3333-4333-8333-333333333333"
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (carol to io.silencelen.andvari.core.client.state.ContactRecord(
                carol, io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 5 }), io.silencelen.andvari.core.trust.TrustGrammar.encodeName("Carol")!!,
                verifiedAt = server.now, compared = false, madeOn = other)))
        }
        assertEquals(PlainResult.DONE, a.contacts.openContacts())
        val asked = assertIs<io.silencelen.andvari.core.app.AccountPrompt.NewPerson>(a.snapshot.account!!.prompts.single())
        assertEquals("Work laptop", asked.madeOn)
        assertEquals("Work laptop", a.snapshot.account!!.contacts!!.contacts.single().madeOn)
        // A list that cannot be read names nothing ("another of your devices"), and a lock forgets the names.
        a.lock()
        server.override[WireRoute.DEVICES] = WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        assertEquals(PlainResult.DONE, a.contacts.openContacts())
        assertEquals("", a.snapshot.account!!.contacts!!.contacts.single().madeOn)
    }

    /** Holds the device list's read on [gate] while [holds] says so; everything else goes through at once. */
    private class HeldDevices(val inner: FakeInstance) : io.silencelen.andvari.core.client.net.WireClient by inner {
        val gate = kotlinx.coroutines.CompletableDeferred<Unit>()
        var holds: () -> Boolean = { false }
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == WireRoute.DEVICES && holds()) gate.await()
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    /**
     * The device names read at an opening survive a recomposition: "update required" composes the vault again while the
     * read waits, which cancelled it with the old vault's scope, and "made on" lines named nothing for the session.
     */
    @Test fun theDeviceNamesReadAtAnOpeningSurviveAVaultComposedAgain() = runBlocking<Unit> { kotlinx.coroutines.withTimeout(60_000) {
        val server = FakeInstance(crypto)
        val held = HeldDevices(server)
        val a = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to held)), MemoryDeviceState(), MemoryDeviceState(), crypto,
                { server.now }, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also {
            it.linksFlow.answersPollMs = Long.MAX_VALUE
            it.start()
        }
        open(a)
        serve(server, a.keeper.session!!.deviceId, otherName = "Work laptop")
        val carol = "33333333-3333-4333-8333-333333333333"
        a.vault!!.store.update { doc ->
            doc.copy(contacts = doc.contacts + (carol to io.silencelen.andvari.core.client.state.ContactRecord(
                carol, io.silencelen.andvari.core.crypto.Bytes.toB64(ByteArray(32) { 5 }), io.silencelen.andvari.core.trust.TrustGrammar.encodeName("Carol")!!,
                verifiedAt = server.now, compared = false, madeOn = other)))
        }
        a.lock()
        // The next opening's read of the list waits.
        held.holds = { a.phase == AppPhase.UNLOCKED && !held.gate.isCompleted }
        assertEquals(io.silencelen.andvari.core.app.VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, strong))
        val first = assertNotNull(a.vault)

        // "Update required" while the read waits: the vault is composed again at once.
        server.override[WireRoute.SYNC] = WireResult.Refused(426, WireError(WireErrors.UPGRADE_REQUIRED, "m"))
        a.keeper.clientFor(server.origin).call(WireRoute.SYNC, authenticated = true) { it }
        assertTrue(assertNotNull(a.vault) !== first, "composed again")
        held.gate.complete(Unit)
        assertEquals(PlainResult.DONE, a.contacts.openContacts())
        assertEquals("Work laptop", a.snapshot.account!!.contacts!!.contacts.single().madeOn, "named in this session")
    } }
}
