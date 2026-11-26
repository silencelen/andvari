package io.silencelen.andvari.desktop.trust

import io.silencelen.andvari.core.app.CopyKey
import io.silencelen.andvari.core.app.InviteResult
import io.silencelen.andvari.core.app.OpenedInvite
import io.silencelen.andvari.core.app.PayloadSource
import io.silencelen.andvari.core.app.fake.FakeDesktopAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Links on the desktop's new path over the fake, with §17's rule for the signed-in invite field. */
class LinksScreensTest {
    private fun at(scene: FakeScene): Pair<FakeDesktopAppApi, TrustModel> {
        val api = FakeScenes.desktopAt(scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), { 0L })
    }

    private val src = File("src/main/kotlin/io/silencelen/andvari/desktop/trust/LinksScreens.kt").readText()

    /** §17: a `/d` link pasted on the signed-in invite field starts no device link, says the API's sentence, and stays. */
    @Test
    fun aDeviceLinkPastedOnTheInviteFieldStartsNothing() {
        val (api, m) = at(FakeScene.LINKS)
        val other = api.script.publicInstance.addAccount("bo@example.com", FakeScenes.PASSWORD)
        m.run({ links.openInvite(api.script.deviceLinkFrom(other, "Laptop"), PayloadSource.PASTED) })
        val said = assertNotNull(m.saidOn(api.snapshot))
        assertEquals(InviteResult.DEVICE_LINK_NOT_HERE, said.result)
        assertEquals(CopyKey.DEVICE_LINK_GOES_ELSEWHERE.english, said.text.shown())
        assertNull(api.snapshot.account?.opened, "nothing opened")
        assertNull(api.snapshot.account?.deviceLink, "no device link started")
        val section = src.substringAfter("fun LinksSection(").substringBefore("\n@Composable")
        assertTrue(section.contains("links.openInvite(p, PayloadSource.PASTED)"))
        assertFalse(src.contains("submitDeviceLink") || src.contains("submitKit") || src.contains("startDeviceLink"), "nothing forwarded to another entry")
    }

    @Test
    fun aConnectLinkOpenedWhileSignedInAsksBeforeConnectingAndCancelComesFirst() {
        val (api, _) = at(FakeScene.OPENED_CONNECT)
        assertIs<OpenedInvite.Connect>(assertNotNull(api.snapshot.account?.opened))
        val opened = src.substringAfter("fun OpenedInviteView(").substringBefore("\n@Composable")
        assertTrue(opened.indexOf("links.dismissOpened()") < opened.indexOf("NamedLinkAct.Connect(opened)"), "Cancel first")
    }

    @Test
    fun anOpenLinkIsShownAsAQrAndItsTextAndACopyIsCleared() {
        val (api, m) = at(FakeScene.LINKS)
        val screen = assertNotNull(api.snapshot.account?.links)
        for (link in screen.links) assertNotNull(m.api.links.linkToShare(link))
        val own = src.substringAfter("private fun OwnLinkView(").substringBefore("\n@Composable")
        assertTrue(own.contains("QrImage(url)") && own.contains("copyWithAutoClear(url, clipboardSeconds(model))"))
        assertFalse(src.contains("openAppLink("))
    }
}
