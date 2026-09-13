package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Audit 2026-09-13 H41: regression pins for the 0.26.2 (2026-08-30 audit) desktop fixes that
 * shipped with no test — G09 (the vault-meta replay signal reaching the user), G37 (a copied
 * one-time code recorded as a use), G36/G50/G63 (export temp survival, create-time mode, the
 * attachment saver's curated errors) and the lock/switch half of G03 (the teardown flush owning
 * the client's close). A fix nothing pins is a fix nothing keeps — each block names its G-row
 * and FAILS if that fix is reverted.
 *
 * Source pins in the [SurfacePinsTest] idiom: these live inside `@Composable`s and private
 * DesktopState helpers this module's pure-JVM suite cannot reach. Ordering assertions first prove
 * both anchors present — `indexOf` of a deleted line is -1, which is less than anything.
 *
 * Already pinned elsewhere (not repeated): G10 (H10 DesktopAsyncFlowsTest +
 * SurfacePinsTest.everyBusyHoldingNetworkLegIsBounded), G22 (H12
 * SurfacePinsTest.theTrashReaderGateMatchesWebAndAndroid), the sign-out half of G03 (H33
 * UsageLedgerSeamsTest), G24.
 */
class RegressionPins0262Test {

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-desktop/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")

    private val ui by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/Ui.kt").readText() }
    private val state by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/DesktopState.kt").readText() }
    private val session by lazy { sourceFile("src/main/kotlin/io/silencelen/andvari/desktop/DesktopSession.kt").readText() }

    private fun assertOrdered(hay: String, first: String, second: String, why: String) {
        val a = hay.indexOf(first)
        val b = hay.indexOf(second)
        assertTrue(a > -1, "$why: missing `$first`")
        assertTrue(b > -1, "$why: missing `$second`")
        assertTrue(a < b, why)
    }

    // ---- G09 (security): the anti-replay diagnostic must not die in CoreLog.Silent ----

    /** Web both console.warns AND shows a calm `meta-regression` notice; desktop detected and
     *  corrected the replay, then discarded the signal. Every engine construction must carry the
     *  log seam that maps the event to the static notice — a second, log-less `SyncEngine(`
     *  would re-open the hole on whichever path used it. */
    @Test
    fun g09_everySyncEngineConstructionSurfacesTheVaultMetaReplayAsANotice() {
        val constructions = Regex("= SyncEngine\\(").findAll(state).map { it.range.first }.toList()
        assertTrue(constructions.isNotEmpty(), "DesktopState must construct the engine somewhere")
        for (at in constructions) {
            val window = state.substring(at, minOf(state.length, at + 240))
            assertTrue(window.contains("log = CoreLog { event, _ ->"), "an engine built without the log seam: $window")
            assertTrue(window.contains("if (event == CoreLog.EVENT_VAULT_META_REPLAY) notice = META_REPLAY_NOTICE"), "the replay event must land on the notice line")
        }
        // Static curated copy, never the event's own detail — the notice surface stays
        // interpolation-free (§F.7). The constant is a plain literal with no `$`.
        val decl = state.substringAfter("const val META_REPLAY_NOTICE =").trimStart()
        val literal = decl.substring(0, decl.indexOf('"', 1) + 1)
        assertFalse(literal.contains("$"), "META_REPLAY_NOTICE must not interpolate: $literal")
        assertEquals(
            "A saved change to one of your vaults looked older than expected and was kept as-is — if a recent change is missing, re-save it.",
            DesktopState.META_REPLAY_NOTICE,
        )
    }

    // ---- G37: copying a one-time code IS a use (spec 02 §8.2) ----

    @Test
    fun g37_theTotpRowRecordsAUseOnCopyLikeThePasswordRowAlreadyDid() {
        assertTrue(
            ui.contains("TotpRow(it, clearSeconds = clipClear, onUsed = { state.recordUse(item.itemId) })"),
            "Detail must hand TotpRow the same recordUse the password CopyRow gets",
        )
        val row = ui.substringAfter("private fun TotpRow(").substringBefore("\n@Composable")
        assertTrue(row.contains("onUsed: () -> Unit = {},"), "the seam exists (no-op default for previews)")
        assertTrue(row.contains("onClick = { onUsed(); copyFailed = !copyWithAutoClear(code, clearSeconds) }"), "…and fires on the copy click, before the clipboard write")
    }

    // ---- G36 / G50: the export temp — created owner-only, and a kept temp that survives exit ----

    private val writer by lazy { state.substringAfter("private fun writeVerifiedAtomically(dest: File, bytes: ByteArray) {").substringBefore("\n    /**") }

    /** F35's rule: the permissions are part of the CREATE. The temp later holds the full
     *  plaintext CSV or a decrypted attachment; created-at-umask-then-chmodded leaves a window
     *  in which an open() keeps its readable fd regardless of the later repair. */
    @Test
    fun g50_thePlaintextTempIsCreatedOwnerOnlyNotRepairedAfterwards() {
        assertOrdered(
            writer,
            "Files.createTempFile(dir.toPath(), \"andvari-\", \".tmp\", *ownerOnly(\"rw-------\"))",
            "restrictToOwner(tmp)",
            "the create-time mode is the braces; restrictToOwner stays only as the belt for the fallback path",
        )
        assertTrue(writer.contains(".getOrElse { File.createTempFile(\"andvari-\", \".tmp\", dir) }"), "Windows / a refusing FS falls back to the plain create")
        assertTrue(session.contains("internal fun ownerOnly(spec: String)"), "one implementation, shared with the session store — no second copy to drift")
    }

    /** java.io.File cannot cancel deleteOnExit, so the deliberately-kept temp — possibly the
     *  only surviving verified copy after the non-atomic fallback replaced dest — vanished at
     *  the next normal exit while the error told the user where it was. */
    @Test
    fun g36_theKeptExportIsRenamedToASurvivorBeforeTheErrorNamesIt() {
        val moveFailure = writer.substringAfter("} catch (t: Throwable) {\n            // Audit G36")
        assertTrue(moveFailure.contains("val survivor = File(dir, \"\${dest.name}.recovered-\${System.currentTimeMillis()}\")"))
        assertOrdered(
            moveFailure,
            "val kept = runCatching { Files.move(tmp.toPath(), survivor.toPath()); survivor }.getOrDefault(tmp)",
            "throw IllegalStateException(\"could not replace \${dest.name}: \${t.message} — the verified export was left at \${kept.name} in the same folder\", t)",
            "the rename happens BEFORE the sentence, and the sentence names the file that will still exist",
        )
        assertFalse(moveFailure.contains("left at \${tmp.name}"), "the error must never name the doomed temp when a survivor exists")
    }

    // ---- G63: the attachment saver surfaces writeVerifiedAtomically's curated sentences ----

    @Test
    fun g63_saveAttachmentToCarriesTheExportErrorCarveOut() {
        assertTrue(
            state.contains("fun saveAttachmentTo(ref: AttachmentRef, dest: File) = op(map = ::exportError"),
            "the third writeVerifiedAtomically caller must map through exportError like backup and CSV do — else its ISE sentences flatten to SOMETHING_WENT_WRONG",
        )
    }

    // ---- G03 (lock/switch legs): the teardown flush owns closing the client ----

    /** The scope is Main-confined: a flush launched in the same statement list as a synchronous
     *  api.close() could never start before the close ran, so the session's last uses were
     *  cancelled and dropped every time. The client's close now rides the bounded flush's
     *  completion; keys and state still drop synchronously. */
    @Test
    fun g03_lockAndSwitchHandTheClientsCloseToTheBoundedFlush() {
        for (fn in listOf("fun lock(reason: String = \"Locked.\") {", "private fun clearSessionForSwitch() {")) {
            val body = state.substringAfter(fn).substringBefore("\n    }")
            assertTrue(body.contains("flushUsageThenClose(); clearUsage(); engine?.close(); api = null; account = null; engine = null"), "$fn must tear down through flushUsageThenClose")
            assertFalse(body.contains("api?.close()"), "$fn must not close the client inline — that is the race")
        }
        val flush = state.substringAfter("private fun flushUsageThenClose() {").substringBefore("\n    }")
        assertTrue(flush.contains("val a = api ?: return"), "the transport is captured BEFORE the caller nulls `api`")
        assertTrue(flush.contains("usage.flushForSession(UsageSession(a, acct)) { a.close() }"), "the close is the flush's continuation, bounded by the recorder")
        assertTrue(state.contains("boundedFlushTimeoutMs = USAGE_FLUSH_TIMEOUT_MS,"), "…under the shared 2 s bound")
    }
}
