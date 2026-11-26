package io.silencelen.andvari.hostile

import io.silencelen.andvari.cli.e2e.Steps
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.PasswordChangeResult
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.SignInAnswer
import io.silencelen.andvari.core.app.VaultUnlockResult
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Handler
import io.silencelen.andvari.hostile.proxy.Resp
import io.silencelen.andvari.hostile.proxy.answer
import io.silencelen.andvari.hostile.proxy.edit
import io.silencelen.andvari.hostile.proxy.editAnswer
import io.silencelen.andvari.hostile.proxy.long
import io.silencelen.andvari.hostile.proxy.obj
import io.silencelen.andvari.hostile.proxy.set
import io.silencelen.andvari.hostile.proxy.str
import kotlinx.coroutines.Dispatchers
import io.silencelen.andvari.core.client.net.WireResult
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Spec 01 §7, "KDF upgrade" and the pending-record rule, against the REAL server through a proxy that lies about the
 * quiet re-key, with an app device (the desktop app's engine, its own session keeper) as the device that re-keys. That
 * device opens from the wrap it keeps itself, not from the keys served at each opening (as the command-line tool does),
 * so a lie about the re-key once left its wrap and the server's verifier apart: the account still opened with the same
 * password, but every proof it made on its session was refused as a wrong password until the person signed in again.
 * Each scenario now ends the same way: the next opening with the password settles the wrap, and a password change on
 * the session (a proof the server checks) is accepted.
 */
class AppQuietReKeyLiesTest {
    private val crypto = createCryptoProvider()
    private val email = "alice@example.org"
    private val newer = "a whole New master password 7 here"
    private val mib = 1024L * 1024

    private fun World.desktop(tag: String): EngineDesktopAppApi {
        val state = MemoryDeviceState()
        val engine = AppEngine(AppPlatform.LINUX, "Desk", dialingTransport(state, server.httpFor(proxy.dial(tag)), AppPlatform.LINUX), state, MemoryDeviceState(),
            crypto, server::now, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.IO)
        return EngineDesktopAppApi(engine).also { it.start() }
    }

    private inline fun <reified T : EntryScreen> EngineDesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** The person types the server's address, confirms its Trust Gate and signs in with the password: the vault opens. */
    private suspend fun World.signedInDesktop(tag: String): EngineDesktopAppApi {
        val app = desktop(tag)
        app.entry.openOwnServer(app.at())
        assertEquals(ServerResult.DONE, app.entry.submitServerAddress(app.at(), origin))
        assertEquals(ServerResult.DONE, app.entry.confirmTrustGate(app.at()))
        assertEquals(ServerResult.DONE, app.entry.signInHere(app.at()))
        assertEquals(SignInAnswer.DONE, app.entry.submitSignIn(app.at(), email, Steps.PASSWORD))
        assertEquals(AppPhase.UNLOCKED, app.snapshot.phase, "the vault opens")
        return app
    }

    private suspend fun EngineDesktopAppApi.relock(password: String): VaultUnlockResult {
        lock()
        return unlock(assertNotNull(snapshot.locked), password)
    }

    /** The policy as the proxy serves it: the real one with its KDF cost replaced. */
    private fun World.policyAsks(ops: Long, memBytes: Long) =
        proxy.on(WireRoute.CLIENT_POLICY, name = "policy $ops/$memBytes", handler = editAnswer { it.edit("kdfParams") { p -> p.set("ops", ops).set("memBytes", memBytes) } })

    /** The account's keys as the real server answered the device's last read of them. */
    private fun World.servedKeys(tag: String): JsonObject = assertNotNull(proxy.last(WireRoute.ACCOUNT_KEYS, tag)?.upstream?.json, "$tag read the account's keys")

    private fun JsonObject.cost(): Pair<Long, Long> = obj("kdfParams")!!.let { it.long("ops")!! to it.long("memBytes")!! }

    /**
     * The end of every scenario: the opening after the lie settles it, a second one sends no password change, and a
     * password change on the session is accepted; the new password then opens the vault.
     */
    private suspend fun World.settles(app: EngineDesktopAppApi, tag: String, cost: Pair<Long, Long>) {
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD), "the same password opens the vault")
        val mark = proxy.mark()
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD))
        assertEquals(emptyList(), sent(tag, WireRoute.PASSWORD_CHANGE, mark), "nothing more is re-keyed")
        assertEquals(cost, servedKeys(tag).cost(), "the server holds the policy's cost")
        assertEquals(PasswordChangeResult.DONE, app.settings.changeMasterPassword(Steps.PASSWORD, newer), "a proof on the session is accepted: ${proxy.tail()}")
        assertEquals(VaultUnlockResult.DONE, app.relock(newer))
    }

    private fun World.sent(tag: String, route: WireRoute, mark: Int) = proxy.requests(route, tag, mark)

    @Test fun aReKeyAnsweredDoneThatTheServerNeverStoredIsSettledByTheNextOpening() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        policyAsks(4, 64 * mib)
        val rule = proxy.on(WireRoute.PASSWORD_CHANGE, "desk", times = 1, handler = answer { Resp.json(200, JsonObject(emptyMap())) })
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD))
        rule.remove()
        assertEquals(1, sent("desk", WireRoute.PASSWORD_CHANGE, 0).size, "the re-key went, and the lie answered it")
        assertEquals(3L to 64 * mib, servedKeys("desk").cost(), "nothing was stored")
        // The next opening adopts the wrap the server holds (the password opens it to the account's own key) and re-keys
        // for real; the opening after it sends nothing; a proof on the session is accepted.
        settles(app, "desk", 4L to 64 * mib)
    }

    @Test fun aReKeyTheServerStoredAndAnsweredWithARefusalIsSettledByTheNextOpening() = world {
        operator()
        member("alice")
        val app = signedInDesktop("desk")
        policyAsks(4, 64 * mib)
        val rule = proxy.on(WireRoute.PASSWORD_CHANGE, "desk", times = 1, handler = Handler { x -> x.forward(); Resp.error(403, "reauth_failed") })
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD), "the person sees nothing of it")
        rule.remove()
        val mark = proxy.mark()
        // The server holds the new wrap; this device dropped it. The next opening adopts it and sends no second re-key.
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD))
        assertEquals(4L to 64 * mib, servedKeys("desk").cost(), "the server stored it")
        assertEquals(emptyList(), sent("desk", WireRoute.PASSWORD_CHANGE, mark))
        settles(app, "desk", 4L to 64 * mib)
    }

    /**
     * The server serves another account's keys (made with the same password, for that account) at an opening: the
     * device tries them, they do not open as this account's, and nothing changes. The device keeps opening from its own
     * wrap and a proof on the session is still accepted.
     */
    @Test fun anotherAccountsWrapServedAtAnOpeningChangesNothing() = world {
        operator()
        member("alice")
        val bob = member("bob")
        val bobsKeys = Json.parseToJsonElement(assertIs<WireResult.Ok<String>>(bob.client(origin).call(WireRoute.ACCOUNT_KEYS, decode = { it })).value).jsonObject
        val app = signedInDesktop("desk")
        // An opening with the password reads the account's keys before it returns: the wrap this device keeps.
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD))
        val own = servedKeys("desk").str("wrappedUvk")
        val swap = proxy.on(WireRoute.ACCOUNT_KEYS, "desk", handler = editAnswer { mine ->
            mine.set("kdfSalt", bobsKeys.str("kdfSalt")!!).set("wrappedUvk", bobsKeys.str("wrappedUvk")!!)
        })
        val mark = proxy.mark()
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD), "the device opens from its own wrap")
        assertTrue(sent("desk", WireRoute.ACCOUNT_KEYS, mark).isNotEmpty(), "the opening read the account's keys")
        assertEquals(emptyList(), sent("desk", WireRoute.PASSWORD_CHANGE, mark), "nothing is sent")
        swap.remove()
        assertNotEquals(own, bobsKeys.str("wrappedUvk"))
        assertEquals(VaultUnlockResult.DONE, app.relock(Steps.PASSWORD))
        assertEquals(own, servedKeys("desk").str("wrappedUvk"), "the server still holds the device's own wrap")
        assertEquals(PasswordChangeResult.DONE, app.settings.changeMasterPassword(Steps.PASSWORD, newer), "a proof on the session is accepted: ${proxy.tail()}")
        assertEquals(VaultUnlockResult.DONE, app.relock(newer))
    }
}
