package io.silencelen.andvari.app.trust

import io.silencelen.andvari.app.autofill.AutofillSave
import io.silencelen.andvari.app.autofill.SavedCredentials
import io.silencelen.andvari.app.autofill.saveWords
import io.silencelen.andvari.app.autofill.unlockFaultWords
import io.silencelen.andvari.core.app.AppPhase
import io.silencelen.andvari.core.app.AppPlatform
import io.silencelen.andvari.core.app.EntryScreen
import io.silencelen.andvari.core.app.OperatorHelpStage
import io.silencelen.andvari.core.app.RoleInVault
import io.silencelen.andvari.core.app.VaultLogState
import io.silencelen.andvari.core.app.content.FakeVaultContent
import io.silencelen.andvari.core.app.fake.FakeAppApi
import io.silencelen.andvari.core.app.fake.FakeScene
import io.silencelen.andvari.core.app.fake.FakeScenes
import io.silencelen.andvari.core.crypto.KeysGoneException
import io.silencelen.andvari.core.crypto.createCryptoProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import java.io.File
import java.nio.file.Files
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Approved sentences that stood where they were not true (the copy page's entries PQ16, PQ9, PZ21, PQ4 and P8): each
 * place is reached in the state that showed the wrong line, and the line it shows now is named by its key.
 */
class UntrueLinesTest {
    private val base = Files.createTempDirectory("andvari-untrue-lines").toFile()

    @AfterTest
    fun cleanup() {
        base.deleteRecursively()
    }

    private fun at(scene: FakeScene): Pair<FakeAppApi, TrustModel> {
        val api = FakeScenes.onPlatform(AppPlatform.ANDROID, scene)
        return api to TrustModel(api, CoroutineScope(Dispatchers.Unconfined), BuildConstants.JOIN_BASE, { 0L }, { false }, {}).also { it.onSnapshot(api.snapshot) }
    }

    private fun key(t: UiText?): Placeholder = assertIs<UiText.Ph>(assertNotNull(t)).placeholder

    private fun unlocked(scene: FakeScene = FakeScene.VAULTS): Pair<FakeAppApi, TrustModel> {
        val (api, m) = at(scene)
        if (api.snapshot.phase == AppPhase.LOCKED) m.run({ unlock(assertNotNull(snapshot.locked), FakeScenes.PASSWORD) })
        m.onSnapshot(api.snapshot)
        assertEquals(AppPhase.UNLOCKED, api.snapshot.phase)
        return api to m
    }

    // ---- (a) "Something went wrong with this vault." only while a vault is open and the fault names it ----

    @Test
    fun aFaultWhileLockedOrUnlockingSaysTheGeneralLine() {
        val (api, m) = at(FakeScene.LOCKED)
        assertEquals(AppPhase.LOCKED, api.snapshot.phase)
        m.act { throw IllegalStateException("x") }
        assertEquals(Placeholder.WENT_WRONG, key(m.saidOn(api.snapshot)?.text), "nothing is open while locked")
        m.run<io.silencelen.andvari.core.app.PlainResult>({ throw IllegalStateException("x") })
        assertEquals(Placeholder.WENT_WRONG, key(m.saidOn(api.snapshot)?.text))
        // Above the screen, a fault that names a vault while locked still says the general line.
        m.fault("some-vault")
        assertEquals(Placeholder.WENT_WRONG, assertNotNull(m.wentWrong.value).text.let(::key))
        // The autofill unlock window: a fault while unlocking is the general line; "the keys are gone" there is an
        // unlock that did not finish (the unlock is what to do again), never "do it again once you've unlocked".
        assertEquals(Placeholder.WENT_WRONG, key(unlockFaultWords(IllegalStateException("x"), api.snapshot)))
        assertEquals(Placeholder.UNLOCK_NOT_FINISHED, key(unlockFaultWords(KeysGoneException(), api.snapshot)))
    }

    @Test
    fun aFaultThatNamesNoVaultSaysTheGeneralLineAndOneThatNamesTheOpenVaultTheVaultsLine() {
        val (_, m) = unlocked()
        m.fault(null)
        assertEquals(Placeholder.WENT_WRONG, key(assertNotNull(m.wentWrong.value).text), "no vault named")
        m.fault(FakeVaultContent.PERSONAL_VAULT_ID)
        assertEquals(Placeholder.VAULT_WENT_WRONG, key(assertNotNull(m.wentWrong.value).text), "a vault named, and open")
        // Signed out: no vault at all, named or not.
        val (_, out) = at(FakeScene.FIRST_RUN)
        out.fault(FakeVaultContent.PERSONAL_VAULT_ID)
        assertEquals(Placeholder.WENT_WRONG, key(assertNotNull(out.wentWrong.value).text))
        out.fault(null)
        assertEquals(Placeholder.WENT_WRONG, key(assertNotNull(out.wentWrong.value).text))
    }

    // ---- (b) a vault's name this device doesn't know is said as a name, and the sentence only where it is true ----

    @Test
    fun aNamelessVaultHasANameKeyAndTheAcceptLineOnlyBeforeItIsAccepted() {
        val (api, _) = unlocked()
        api.script.strangerSharesVault("Mallory")
        val stranger = assertNotNull(api.snapshot.account).vaults.single { it.log == VaultLogState.CONNECT_FIRST }
        assertNull(stranger.name)
        assertEquals(UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN_TITLE).shown(), vaultRowName(stranger))
        assertNotEquals(UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN).shown(), vaultRowName(stranger), "never the sentence as its name")
        assertEquals(Placeholder.VAULT_NAME_NOT_KNOWN, key(nameOnceAcceptedLine(stranger)), "an offer not accepted yet: the line stands under it")

        // An ACCEPTED vault whose key was refused: accepting is done and will not show the name.
        val (states, _) = unlocked(FakeScene.VAULT_STATES)
        val refused = assertNotNull(states.snapshot.account).vaults.single { it.log == VaultLogState.KEY_REFUSED }
        if (refused.name == null) {
            assertEquals(UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN_TITLE).shown(), vaultRowName(refused))
        }
        assertNull(nameOnceAcceptedLine(refused))
        // Every row of every state: the sentence is never the name.
        for (row in assertNotNull(states.snapshot.account).vaults) {
            assertNotEquals(UiText.ph(Placeholder.VAULT_NAME_NOT_KNOWN).shown(), vaultRowName(row), row.log.name)
            if (row.log != VaultLogState.CONNECT_FIRST && row.log != VaultLogState.CONFIRM_FIRST) assertNull(nameOnceAcceptedLine(row), row.log.name)
        }
        // The three places that show a vault's name read it from vaultRowName.
        val screens = File("src/main/kotlin/io/silencelen/andvari/app/trust/VaultScreens.kt").readText()
        assertTrue(screens.contains("val name = vaultRowName(v)") && screens.contains("Text(vaultRowName(v), style = MaterialTheme.typography.titleLarge"))
        assertTrue(File("src/main/kotlin/io/silencelen/andvari/app/trust/AccountScreens.kt").readText().contains("PageScaffold(UiText.Plain(vaultRowName(sharingVault))"))
        assertTrue(screens.contains("nameOnceAcceptedLine(v)?.let { Quiet(it) }"))
    }

    // ---- (c) a save not made: why, in words true of it ----

    private val crypto = createCryptoProvider()
    private val creds = SavedCredentials(username = "me@example.com", password = "hunter2-secret", webDomain = null, appPackage = "com.example.app", webScheme = null)

    private fun unpublished() = AndroidSaveQueue(File(base, "q-${System.nanoTime()}"))

    @Test
    fun aSaveWithNobodySignedInOrAPolicyThatForbidsItSaysSoNeverUnlock() {
        // Nobody signed in: the first screen.
        val (first, _) = at(FakeScene.FIRST_RUN)
        val nobody = AutofillSave.saveSession(first.snapshot)
        val o1 = AutofillSave.capture(unpublished(), crypto, creds, false, nobody, 1_000L)
        assertEquals(AutofillSave.Outcome.NOT_SIGNED_IN, o1)
        assertEquals(Placeholder.SAVE_NOT_SIGNED_IN, key(saveWords(o1)))

        // Signed in, locked, and no key: never the server's policy (the list of caught logins is outside it, decided on
        // 2026-11-18), only "not saved".
        val (locked, _) = at(FakeScene.LOCKED)
        val o2 = AutofillSave.capture(unpublished(), crypto, creds, false, AutofillSave.saveSession(locked.snapshot), 1_000L)
        assertEquals(AutofillSave.Outcome.REFUSED, o2)
        assertEquals(Placeholder.SAVE_REFUSED, key(saveWords(o2)))

        // Unlocked under a policy that forbids keeping data here, with no key: the same.
        val (api, m) = unlocked()
        api.script.publicInstance.offlineCacheAllowed = false
        api.script.changed()
        m.onSnapshot(api.snapshot)
        assertEquals(AutofillSave.Outcome.REFUSED, AutofillSave.capture(unpublished(), crypto, creds, false, AutofillSave.saveSession(api.snapshot), 1_000L))
        // Unlocked under a policy that allows it, with no key yet: why is not known, so only "not saved".
        api.script.publicInstance.offlineCacheAllowed = true
        api.script.changed()
        val allowed = assertNotNull(api.snapshot.account).policy
        if (allowed.known && allowed.offlineCacheAllowed) {
            val o3 = AutofillSave.capture(unpublished(), crypto, creds, false, AutofillSave.saveSession(api.snapshot), 1_000L)
            assertEquals(AutofillSave.Outcome.REFUSED, o3)
            assertEquals(Placeholder.SAVE_REFUSED, key(saveWords(o3)))
        }
        // No outcome says "unlock" any more: every outcome's line is one of these keys.
        assertEquals(
            setOf(Placeholder.SAVE_QUEUED, Placeholder.SAVE_NOT_SIGNED_IN, Placeholder.SAVE_NOT_NOW, Placeholder.SAVE_REFUSED),
            AutofillSave.Outcome.entries.map { key(saveWords(it)) }.toSet(),
        )
    }

    // ---- (d) a request for the operator's help: the stage's name in the list, the requester's own lines on their screen ----

    @Test
    fun theListOfLiveRequestsNamesTheStageOnlyAndTheRequesterReadsTheirOwnLines() {
        val (api, m) = unlocked()
        m.run({ recovery.openRecovery() })
        assertNotNull(api.script.someoneAsksOperator(AppPlatform.IOS))
        assertNotNull(api.script.someoneAsksOperator(AppPlatform.ANDROID)).stage = OperatorHelpStage.AWAITING_OPERATOR
        api.script.changed()
        val rows = assertNotNull(assertNotNull(api.snapshot.account).recovery).requests
        val holding = rows.first { it.stage == OperatorHelpStage.HOLDING }
        val awaiting = rows.first { it.stage == OperatorHelpStage.AWAITING_OPERATOR }
        assertEquals(Placeholder.RECOVERY_ROW_STAGE_HOLDING, key(requestRowStage(holding.stage)))
        assertEquals(Placeholder.RECOVERY_ROW_STAGE_AWAITING_OPERATOR, key(requestRowStage(awaiting.stage)))
        for (r in rows) {
            val line = requestLine(r).shown()
            assertTrue(line.contains(requestRowStage(r.stage).shown()), line)
            assertTrue(!line.contains(operatorHelpStageLine(r.stage).shown()), "never the requester's own line in the list: $line")
        }

        // The requester's own screen: the code is drawn above the stage's line, whose key is the requester's own.
        val (own, _) = at(FakeScene.OPERATOR_HELP_HOLDING)
        val screen = assertIs<EntryScreen.OperatorHelp>(own.snapshot.entry)
        assertEquals(Placeholder.OPERATOR_HELP_HOLDING, key(operatorHelpStageLine(screen.stage)))
        assertEquals(Placeholder.OPERATOR_HELP_AWAITING_OPERATOR, key(operatorHelpStageLine(OperatorHelpStage.AWAITING_OPERATOR)))
        val body = File("src/main/kotlin/io/silencelen/andvari/app/trust/LinkAndRecoveryScreens.kt").readText()
            .substringAfter("internal fun OperatorHelpScreen(").substringBefore("\n}\n")
        assertTrue(body.indexOf("Text(screen.requestCode.joinToString(\" \")") in 0 until body.indexOf("Say(operatorHelpLine(screen))"), "the code stands above the line")
    }

    @Test
    fun aRequestEndedFromTheAccountsSideSaysWhatIsTrueOfEveryCause() {
        // "Vetoed" is told for a request a signed-in device cancelled, one the server ended after a password change,
        // recovery turned off or a recovery, and one ended by whoever runs the server: the shared code's line is true of
        // each (OperatorHelpEndedByServerTest plays the last). The phone's own line for it is gone.
        val (scene, _) = at(FakeScene.OPERATOR_HELP_VETOED)
        val vetoed = assertIs<EntryScreen.OperatorHelp>(scene.snapshot.entry)
        assertEquals(OperatorHelpStage.VETOED, vetoed.stage)
        assertEquals(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_ENDED, vetoed.endedLine)
        assertEquals(UiText.of(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_ENDED).shown(), operatorHelpLine(vetoed).shown())
        assertFalse(Placeholder.entries.any { it.name == "OPERATOR_HELP_ENDED_FROM_ACCOUNT" }, "the phone's own line is gone")
        val (api, m) = at(FakeScene.OPERATOR_HELP_HOLDING)
        api.script.accountDeviceCancelsRequest()
        m.run({ entry.refreshOperatorHelp(assertIs<EntryScreen.OperatorHelp>(snapshot.entry)) })
        val now = assertIs<EntryScreen.OperatorHelp>(api.snapshot.entry)
        assertEquals(OperatorHelpStage.VETOED, now.stage)
        assertEquals(UiText.of(io.silencelen.andvari.core.app.CopyKey.ASSIST_REQUEST_ENDED).shown(), operatorHelpLine(now).shown())
    }

    // ---- (e) an ownership offer: a line for each reader ----

    @Test
    fun anOfferSaysOneLineToThePersonOfferedAnotherToOtherMembersAndTheNoteOnlyToTheOwner() {
        val (api, m) = unlocked()
        val me = assertNotNull(api.script.publicInstance.accounts[FakeScenes.EMAIL])
        fun family() = me.vaults.first { it.name == "Family" }
        fun row() = assertNotNull(api.snapshot.account).vaults.first { it.name == "Family" }

        // The owner offers it to a member: the owner reads the owner's note.
        m.run({ vaults.openMembers(row()) })
        val to = assertNotNull(api.snapshot.account?.members).members.first { it.role != RoleInVault.OWNER && it.who is io.silencelen.andvari.core.app.PersonName.Contact }
        m.run({ vaults.offerOwnership(to) })
        m.act { vaults.closeMembers() }
        val asOwner = row()
        val offer = assertNotNull(asOwner.offer)
        assertTrue(!offer.toMe)
        assertEquals(
            UiText.approvedNamed(Approved.OWNERSHIP_OFFER_NOTE, NameSlot.said(personLine(offer.to).shown()), vaultSlot(asOwner.name), NameSlot.said("1 Dec 2026")).shown(),
            offerLine(asOwner, offer, "1 Dec 2026").shown(),
            "the owner's own note",
        )

        // A member who is neither the owner nor the person offered: the line naming the person offered.
        family().role = RoleInVault.WRITER
        api.script.changed()
        val asMember = row()
        val line = offerLine(asMember, assertNotNull(asMember.offer), "1 Dec 2026")
        assertEquals(Placeholder.VAULT_OFFER, key(line))
        assertEquals(listOf(personLine(to.who).shown()), assertIs<UiText.Ph>(line).args, "it names the person offered")
        assertTrue(offerLine(asMember, assertNotNull(asMember.offer), "1 Dec 2026").shown() != offerLine(asOwner, offer, "1 Dec 2026").shown())

        // The person offered: their own line, never "You has been asked".
        family().offer = null
        api.script.ownerOffersOwnership(family(), 14)
        val asOffered = row()
        val mine = assertNotNull(asOffered.offer)
        assertTrue(mine.toMe)
        assertEquals(Placeholder.VAULT_OFFER_TO_YOU, key(offerLine(asOffered, mine, "1 Dec 2026")))
    }
}
