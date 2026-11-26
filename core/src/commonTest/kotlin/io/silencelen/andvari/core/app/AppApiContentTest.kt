package io.silencelen.andvari.core.app

import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The vault's content on the app API, walked through the fake: there only while unlocked, new at every unlock. */
class AppApiContentTest {
    @Test
    fun theContentIsThereOnlyWhileUnlockedAndIsNewAtEveryUnlock() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        val first = assertNotNull(app.content)
        assertTrue(first === app.fakeContent, "the scripting handle is the same object")
        val before = app.account.contentRevision
        assertEquals(before, first.state.revision)

        // A change of the content's state publishes a snapshot that carries its revision.
        val id = assertNotNull(app.fakeContent).seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        assertIs<ActionResult.Ok>(await { first.syncQuietly() })
        first.setQuery("Bank")
        assertTrue(app.account.contentRevision > before)
        assertEquals(first.state.revision, app.account.contentRevision)
        assertTrue(first.state.items.any { it.itemId == id })

        app.lock()
        assertNull(app.content, "nothing of the vault while locked")
        assertNull(app.fakeContent)
        assertIs<ActionResult.NotDone>(await { first.syncQuietly() }, "a closed instance does nothing")

        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        val second = assertNotNull(app.content)
        assertFalse(second === first, "a new instance per unlock")
        // The fake's content survives a lock and an unlock, as the engine's device copy does.
        assertTrue(second.state.items.any { it.itemId == id }, "what the content held before the lock is still there")
        assertTrue(second === app.fakeContent)

        // A save asked for once the lock closed the content is said at the next unlock, once, with its kind.
        app.lock()
        assertIs<ActionResult.NotDone>(await { second.saveLogin(null, LoginInput("Typed late", "me", "pw", emptyList(), "", "", false), null) })
        assertEquals(VaultUnlockResult.DONE, await { app.unlock(assertNotNull(app.snapshot.locked), PW) })
        val third = assertNotNull(app.content)
        assertEquals(io.silencelen.andvari.core.app.content.ContentNoticeKind.LOCK, third.state.noticeKind)
        assertEquals(listOf("Typed late"), third.state.lockCut.map { it.name })

        // Signing out and in again starts empty.
        assertEquals(PlainResult.DONE, await { app.signOut() })
    }

    @Test
    fun aFakeGivenAProviderRunsItsContentOverIt() {
        val real = io.silencelen.andvari.core.crypto.createCryptoProvider()
        var used = 0
        val counting = object : io.silencelen.andvari.core.crypto.CryptoProvider by real {
            override fun randomBytes(n: Int): ByteArray {
                used++
                return real.randomBytes(n)
            }
        }
        val app = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.VAULTS, counting)
        val fake = assertNotNull(app.fakeContent)
        val id = fake.seedLogin(FakeVaultContent.PERSONAL_VAULT_ID, "Bank", "me", "pw", "https://bank.example")
        fake.seedAttachment(id, "a.txt", byteArrayOf(1, 2, 3))
        assertTrue(used > 0, "the file's key comes from the provider the fake was given")
    }

    @Test
    fun signingOutClosesTheContent() {
        val app = FakeScenes.at(FakeScene.VAULTS)
        val c = assertNotNull(app.content)
        assertEquals(PlainResult.DONE, await { app.signOut() })
        assertNull(app.content)
        assertIs<ActionResult.NotDone>(await { c.syncQuietly() })
    }

    @Test
    fun underAForkTheContentOpensReadOnly() {
        val stopped = FakeScenes.at(FakeScene.LOCKED_SERVER_STOPPED)
        assertEquals(QuickUnlockResult.DONE, await { stopped.quickUnlock(assertNotNull(stopped.snapshot.locked)) })
        assertTrue(assertNotNull(stopped.content).state.serverStopped)
    }
}
