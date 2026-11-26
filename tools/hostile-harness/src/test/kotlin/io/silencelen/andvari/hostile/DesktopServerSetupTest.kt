package io.silencelen.andvari.hostile

import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.CreateAccountResult
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.NewAccountInput
import io.silencelen.andvari.core.app.RegistrationVia
import io.silencelen.andvari.core.app.ServerResult
import io.silencelen.andvari.core.app.ServerSetupStep
import io.silencelen.andvari.core.app.engine.AppEngine
import io.silencelen.andvari.core.app.engine.EngineDesktopAppApi
import io.silencelen.andvari.core.app.engine.dialingTransport
import io.silencelen.andvari.core.client.MemoryDeviceState
import io.silencelen.andvari.core.crypto.createCryptoProvider
import io.silencelen.andvari.core.model.wire.WireRoute
import io.silencelen.andvari.hostile.proxy.Resp
import kotlinx.coroutines.Dispatchers
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The desktop app's own path through a server's setup (design §6.7), against the REAL server stopped at its setup link,
 * through the app interface as the desktop drives it (the desktop app's failure of 2026-11-16, reproduced). Before the
 * fix the card 0 upload went without the session's bearer (the keeper sent it only to an origin with a pin, and none
 * exists before card 0), the server answered `401`, the screen said NOT_UPLOADED and the retry answered FAILED. The
 * scripted servers never looked at bearers, so they did not see it.
 */
class DesktopServerSetupTest {
    private val crypto = createCryptoProvider()
    private val password = "correct horse Battery 9 staple"

    private fun World.desktop(tag: String): EngineDesktopAppApi {
        val state = MemoryDeviceState()
        val engine = AppEngine(AppPlatform.LINUX, "Desk", dialingTransport(state, server.httpFor(proxy.dial(tag)), AppPlatform.LINUX), state, MemoryDeviceState(),
            crypto, server::now, baked = null, storeBuild = false, stores = null, main = Dispatchers.Unconfined, work = Dispatchers.IO)
        return EngineDesktopAppApi(engine).also { it.start() }
    }

    private inline fun <reified T : EntryScreen> EngineDesktopAppApi.at(): T = assertIs<T>(snapshot.entry, "on ${snapshot.entry}")

    /** The setup link typed into "Use your own server", then the sign-up form: the server setup screen. */
    private suspend fun EngineDesktopAppApi.register(link: String): EntryScreen.ServerSetup {
        entry.openOwnServer(at())
        assertEquals(ServerResult.DONE, entry.submitServerAddress(at(), link))
        val form = at<EntryScreen.CreateAccount>()
        assertEquals(RegistrationVia.SETUP_LINK, form.via)
        assertEquals(CreateAccountResult.DONE, entry.createAccount(form, NewAccountInput("op@example.org", "Operator", password, true)))
        return at()
    }

    @Test fun aFreshServersSetupFinishesFromTheDesktopAndCardZeroIsPinned() = world {
        val app = desktop("desk")
        val setup = app.register(server.setupLink)
        assertEquals(ServerSetupStep.FINISHED, setup.step, "the server's answers: ${proxy.tail()}")
        assertTrue(proxy.requests(WireRoute.INSTANCE_CARD_PUT, "desk", 0).isNotEmpty())
        assertNotNull(setup.details, "card 0 is pinned (the details come from this device's own setup pin)")
    }

    /**
     * The upload is stored but its answer is lost: NOT_UPLOADED; the retry with the right password pins the card 0 the
     * server now serves, which this account signed itself, and sends no second card.
     */
    @Test fun aLostAnswerToCardZeroIsFinishedByTheRetry() = world {
        val app = desktop("desk")
        proxy.on(WireRoute.INSTANCE_CARD_PUT, "desk", times = 1) { x ->
            x.forward()
            Resp.error(503, "unavailable")
        }
        val setup = app.register(server.setupLink)
        assertEquals(ServerSetupStep.NOT_UPLOADED, setup.step)
        assertEquals(ServerResult.WRONG_PASSWORD, app.entry.retryServerSetup(setup, "not the password at all"))
        assertEquals(ServerResult.DONE, app.entry.retryServerSetup(setup, password), "the server's answers: ${proxy.tail()}")
        assertEquals(ServerSetupStep.FINISHED, app.at<EntryScreen.ServerSetup>().step)
        assertNotNull(app.at<EntryScreen.ServerSetup>().details)
        assertEquals(1, proxy.requests(WireRoute.INSTANCE_CARD_PUT, "desk", 0).size, "no second card was sent")
    }

    /** The upload is refused outright (nothing stored): the retry with the right password signs and uploads card 0. */
    @Test fun aRefusedCardZeroIsUploadedByTheRetry() = world {
        val app = desktop("desk")
        proxy.on(WireRoute.INSTANCE_CARD_PUT, "desk", times = 1) { Resp.error(503, "unavailable") }
        val setup = app.register(server.setupLink)
        assertEquals(ServerSetupStep.NOT_UPLOADED, setup.step)
        assertEquals(ServerResult.DONE, app.entry.retryServerSetup(setup, password), "the server's answers: ${proxy.tail()}")
        assertNotNull(app.at<EntryScreen.ServerSetup>().details)
    }
}
