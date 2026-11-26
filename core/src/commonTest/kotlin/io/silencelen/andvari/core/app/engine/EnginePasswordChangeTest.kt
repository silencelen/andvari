package io.silencelen.andvari.core.app.engine

import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CodeResult
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.KitConfirmResult
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignUpStartResult
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.client.net.NoAnswerKind
import io.silencelen.andvari.core.client.net.WireClient
import io.silencelen.andvari.core.client.net.WireResult
import io.silencelen.andvari.core.client.onboard.FakeInstance
import io.silencelen.andvari.core.client.session.BearerTransport
import io.silencelen.andvari.core.crypto.KdfParams
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/**
 * A password change survives a lost answer (the device keeps the new wrap as pending before
 * it sends, and the next unlock settles it with whichever password opens, against what the server says), and the KDF
 * cost of the new password is never lower than the account already had, nor than the policy asks within the fence.
 */
class EnginePasswordChangeTest {
    private val crypto = createCryptoProvider()
    private val strong = "correct horse Battery 9 staple"
    private val newer = "a whole New master password 7 here"

    /** [inner], whose answer to a password change is lost: after the server applied it ([applied]), or before. */
    private class LostAnswer(private val inner: FakeInstance) : WireClient by inner {
        var lose = false
        var applied = true
        override suspend fun <T> call(route: WireRoute, pathParams: Map<String, String>, query: String?, bodyJson: String?, authenticated: Boolean, decode: (String) -> T): WireResult<T> {
            if (route == WireRoute.PASSWORD_CHANGE && lose) {
                if (applied) inner.call(route, pathParams, query, bodyJson, authenticated, decode)
                return WireResult.NoAnswer(NoAnswerKind.TRANSPORT)
            }
            return inner.call(route, pathParams, query, bodyJson, authenticated, decode)
        }
    }

    private class Env(val server: FakeInstance, val wire: LostAnswer, val app: EngineAppApi)

    private suspend fun env(): Env {
        val server = FakeInstance(crypto)
        val wire = LostAnswer(server)
        val a = EngineAppApi(
            AppEngine(AppPlatform.ANDROID, "Pixel", BearerTransport(mapOf(server.origin to wire)), MemoryDeviceState(), MemoryDeviceState(), crypto, { server.now },
                baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.Unconfined),
        ).also { it.start() }
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
        return Env(server, wire, a)
    }

    private inline fun <reified T : EntryScreen> EngineAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    private suspend fun EngineAppApi.relock(password: String): VaultUnlockResult {
        lock()
        return unlock(snapshot.locked!!, password)
    }

    @Test fun aChangeTheServerTookWhoseAnswerWasLostOpensWithTheNewPassword() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        e.wire.lose = true
        assertEquals(PasswordChangeResult.UNREACHABLE, a.settings.changeMasterPassword(strong, newer))
        e.wire.lose = false
        // The server holds the new password: the person is never told "wrong password" for the one they just set.
        assertEquals(VaultUnlockResult.DONE, a.relock(newer))
        // The opening read what the server holds and settled it: the new password's wrap is this device's own now.
        assertEquals(VaultUnlockResult.DONE, a.relock(newer))
        assertEquals(e.server.accounts.values.single().wrappedUvk, a.keeper.established!!.accountKeys.wrappedUvk)
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, a.relock(strong), "the old password no longer opens it")
        // And it re-authenticates there: the next change goes through with it.
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, newer))
        assertEquals(PasswordChangeResult.DONE, a.settings.changeMasterPassword(newer, strong))
    }

    /**
     * The server takes a change whose answer is lost, and the person
     * presses Change again with the same form. Before, the second change replaced the first pending wrap and its refusal
     * dropped it, leaving this device on the old password while the server held the new one. Now the first is settled
     * against the server's keys before anything more is sent: the new password is the one in force, the old one proves
     * nothing, and the device's wrap is the server's.
     */
    @Test fun theSameChangeSentAgainAfterALostAnswerSettlesTheFirstAndLeavesTheNewPasswordInForce() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        e.wire.lose = true
        assertEquals(PasswordChangeResult.UNREACHABLE, a.settings.changeMasterPassword(strong, newer))
        e.wire.lose = false
        val changes = e.server.calls.count { it == WireRoute.PASSWORD_CHANGE }
        assertEquals(PasswordChangeResult.WRONG_PASSWORD, a.settings.changeMasterPassword(strong, newer), "the old password is not the server's any more")
        assertEquals(changes, e.server.calls.count { it == WireRoute.PASSWORD_CHANGE }, "nothing more sent")
        assertEquals(VaultUnlockResult.DONE, a.relock(newer), "the new password opens this device")
        assertEquals(e.server.accounts.values.single().wrappedUvk, a.keeper.established!!.accountKeys.wrappedUvk, "the device's wrap is the server's")
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, a.relock(strong))
        assertEquals(VaultUnlockResult.DONE, a.unlock(a.snapshot.locked!!, newer))
        // It proves here: a change with the new password goes through.
        assertEquals(PasswordChangeResult.DONE, a.settings.changeMasterPassword(newer, strong))
    }

    @Test fun aChangeTheServerNeverGotIsDroppedAtTheNextOpening() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        e.wire.lose = true
        e.wire.applied = false
        assertEquals(PasswordChangeResult.UNREACHABLE, a.settings.changeMasterPassword(strong, newer))
        e.wire.lose = false
        assertEquals(VaultUnlockResult.DONE, a.relock(strong), "the old password still opens it")
        // The opening read the server's wrap: the change never landed, so its pending wrap goes.
        assertEquals(VaultUnlockResult.WRONG_PASSWORD, a.relock(newer))
        assertEquals(VaultUnlockResult.DONE, a.relock(strong))
    }

    @Test fun theNewPasswordIsDerivedAtTheHigherOfTheAccountsCostAndThePolicys() = runBlocking<Unit> {
        val e = env()
        val a = e.app
        // A policy asking for more than the account has, within the fence: read at the next opening.
        e.server.policyKdf = KdfParams(ops = 4)
        assertEquals(VaultUnlockResult.DONE, a.relock(strong))
        assertEquals(PasswordChangeResult.DONE, a.settings.changeMasterPassword(strong, newer))
        assertEquals(4L, e.server.accounts.values.single().kdfParams.ops, "never the default when more is asked")
        // A policy asking for less never lowers it again.
        e.server.policyKdf = KdfParams.DEFAULT
        assertEquals(VaultUnlockResult.DONE, a.relock(newer))
        assertEquals(PasswordChangeResult.DONE, a.settings.changeMasterPassword(newer, strong))
        assertEquals(4L, e.server.accounts.values.single().kdfParams.ops, "the account's cost is never lowered")
    }
}
