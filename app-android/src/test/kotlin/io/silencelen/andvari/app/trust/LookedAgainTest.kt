package io.silencelen.andvari.app.trust

import io.silencelen.andvari.core.app.AddressMismatchFor
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.InstanceCardState
import io.silencelen.andvari.core.app.LinkLifetimes
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import java.io.File
import java.util.Locale
import java.util.TimeZone
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * What the last look at the drawn screens listed and was fixed in this round, each pinned here; the redrawn images
 * (named in each test) are the before and after.
 */
class LookedAgainTest {
    private fun src(name: String) = File("src/main/kotlin/io/silencelen/andvari/app/trust/$name").readText()

    /** The body of the composable or function [fn] in [text], up to the next top-level declaration. */
    private fun body(text: String, fn: String): String {
        val start = text.indexOf(fn)
        assertTrue(start >= 0, "$fn is gone")
        val end = Regex("""\n(@Composable|internal fun|private fun|fun |/\*\*)""").find(text, start + fn.length)?.range?.first ?: text.length
        return text.substring(start, end)
    }

    private var locale: Locale = Locale.getDefault()
    private var zone: TimeZone = TimeZone.getDefault()

    @BeforeTest
    fun usEnglish() {
        Locale.setDefault(Locale.US)
        TimeZone.setDefault(TimeZone.getTimeZone("America/Los_Angeles"))
    }

    @AfterTest
    fun restore() {
        Locale.setDefault(locale)
        TimeZone.setDefault(zone)
    }

    /** opened-connect, opened-key-changed, opened-other-instance, opened-trust-gate, opened-server-changed. */
    @Test
    fun aLinkSomeoneOpenedIsAnsweredFirstOnAScreenOfItsOwn() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.OPENED_CONNECT)
        assertNotNull(assertNotNull(api.snapshot.account).opened, "the scene opens a link")
        val shell = body(src("AccountScreens.kt"), "internal fun AccountShell(")
        val routed = shell.indexOf("account.opened?.let { return OpenedLinkPage(")
        assertTrue(routed > 0 && routed < shell.indexOf("when (page) {"), "an opened link is its own screen, before any page")
        val links = src("LinksScreens.kt")
        assertTrue("account.opened" !in body(links, "internal fun LinksSection("), "no longer at the bottom of Sharing")
        val view = body(links, "internal fun OpenedInviteView(")
        assertTrue(view.indexOf("OpenedInviteBody(") in 0 until view.indexOf("links.dismissOpened()"), "the question and its actions, then the way out")
        assertTrue("ActiveBackHandler(" in body(links, "internal fun OpenedLinkPage("), "Back is the way out too")
    }

    /** locked and link-device-password, small phone at the largest font. */
    @Test
    fun aPasswordStepNamesTheAccountAndServerOnce() {
        val lock = body(src("AccountScreens.kt"), "internal fun LockScreen(")
        assertTrue("PasswordStepTitle(lockTitle(locked), locked.prompt.instance)" in lock)
        assertTrue("InstanceName(" !in lock, "the server is not named a second time")
        assertTrue("if (largeFont()) SigilMark(" in lock, "the wordmark gives way at the largest font")
        val link = body(src("LinkAndRecoveryScreens.kt"), "internal fun LinkDevicePasswordScreen(")
        assertTrue("PasswordStepTitle(" in link && "InstanceName(" !in link)
        assertEquals(1.5f, LARGE_FONT_SCALE)
    }

    /** Every Sharing and Settings page: the way back to the vault was a padlock. */
    @Test
    fun theWayBackIsTheMirroredBackArrowAndNoPadlockIsUsedForIt() {
        val bar = body(src("VaultHome.kt"), "internal fun PageTopBar(")
        assertTrue("Icons.AutoMirrored.Filled.ArrowBack" in bar)
        val main = File("src/main/kotlin/io/silencelen/andvari/app").walkTopDown().filter { it.extension == "kt" }
        main.forEach { f -> assertTrue(!Regex("""Icons\.\w+\.Lock\b""").containsMatchIn(f.readText()), "${f.name} draws a padlock") }
    }

    /** card-kind-change-put-off: "Not now" left the gate on screen, unchanged. */
    @Test
    fun notNowPutsTheQuestionOffAndSaysWhenItComesBack() {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, FakeScene.CARD_KIND_CHANGE_PUT_OFF)
        val card = assertIs<InstanceCardState.KindChanged>(assertNotNull(api.snapshot.instance).card)
        assertTrue(card.putOff)
        val gate = body(src("EntryScreens.kt"), "internal fun KindChangeGate(")
        val putOff = gate.indexOf("if (card.putOff && !reopened)")
        assertTrue(putOff >= 0 && putOff < gate.indexOf("TrustGateBody(card.gate)"), "put off: the gate is not shown")
        assertTrue("Placeholder.KIND_CHANGE_PUT_OFF" in gate)
        assertTrue("next time you unlock" in UiText.ph(Placeholder.KIND_CHANGE_PUT_OFF).shown(), "it says when it is asked again")
        assertTrue("reopened = false" in gate, "Not now after reopening puts it off again")
    }

    /** operator-help-holding, history (seconds), devices ("Dec 31, 1969"). */
    @Test
    fun timesAreToTheMinuteAndAnUnknownTimeSaysSo() {
        val ms = 1_763_350_215_000L // 2025-11-16, with seconds in it
        val withSeconds = Regex("""\d:\d\d:\d\d""")
        assertTrue(!withSeconds.containsMatchIn(Dates.dateTime(ms)), Dates.dateTime(ms))
        assertTrue(Dates.dateTime(ms).contains("2025"))
        for (unknown in listOf(0L, -1L)) {
            for (shown in listOf(Dates.dateTime(unknown), Dates.date(unknown))) {
                assertTrue(shown == UiText.ph(Placeholder.TIME_NOT_KNOWN).shown() && "1969" !in shown && "1970" !in shown, shown)
            }
        }
        val trust = File("src/main/kotlin/io/silencelen/andvari/app/trust").walkTopDown().filter { it.extension == "kt" && it.name != "Dates.kt" }
        trust.forEach { f ->
            val t = f.readText()
            assertTrue("getDateTimeInstance()" !in t, "${f.name}: a time with seconds")
            assertTrue(!Regex("""\.format\((java\.util\.)?Date\(""").containsMatchIn(t) || f.name == "KitScreens.kt", "${f.name}: a date formatted outside Dates")
        }
        // The kit's printed page keeps its own form; only its screen goes through Dates.
        assertTrue("Dates.date(doc.madeAtMs, DateFormat.LONG)" in src("KitScreens.kt"))
    }

    /** address-mismatch, address-mismatch-kit. */
    @Test
    fun twoAddressesThatDifferAreEachSaidToBeWhatTheyAre() {
        val labels = AddressMismatchFor.entries.map { dialedAddressLabel(it) }
        assertTrue(labels.none { it == Placeholder.ADDRESS_CARD_NAMES })
        assertEquals(Placeholder.ADDRESS_YOU_TYPED, dialedAddressLabel(AddressMismatchFor.TYPED_ADDRESS))
        val screen = body(src("EntryScreens.kt"), "internal fun AddressMismatchScreen(")
        assertTrue(screen.indexOf("dialedAddressLabel(screen.opening)") < screen.indexOf("screen.dialed"))
        assertTrue(screen.indexOf("Placeholder.ADDRESS_CARD_NAMES") < screen.indexOf("screen.cardNames"))
    }

    /** sign-up-email, links, settings, kit-reveal. */
    @Test
    fun theSmallerOnes() {
        assertTrue("Title(UiText.of(CopyKey.SERVER_CREATE_ACCOUNT))" in body(src("AccountEntryScreens.kt"), "internal fun SignUpEmailScreen("), "sign-up has a title")
        val words = connectLifetimes.map { lifetimeWords(it).shown() }
        assertEquals(3, words.toSet().size)
        words.forEach { w -> assertTrue("1440" !in w && "10080" !in w && !w.startsWith("⟦" + Placeholder.LINK_MINUTES.gloss), w) }
        assertTrue("15" in lifetimeWords(LinkLifetimes.IN_PERSON_MINUTES).shown())
        assertTrue("7" in lifetimeWords(LinkLifetimes.CONNECT_LONGEST_MINUTES).shown())
        val section = body(src("LinksScreens.kt"), "internal fun LinksSection(")
        assertTrue("RadioButton(" in section && "LINK_MINUTES" !in section)
        assertTrue("\"#\${" !in src("AccountScreens.kt"), "no bare #n after the operator key")
        val id = "0123456789abcdef0123456789abcdef"
        assertEquals("0123 4567 89ab cdef 0123 4567 89ab cdef", groupedForReading(id))
        val kit = src("KitScreens.kt")
        assertTrue("groupedForReading(doc.accountId)" in kit, "the kit's screen groups the account ID")
        assertTrue("line(d.accountIdLine.english)" in kit, "the printed kit keeps the specification's form")
    }
}
