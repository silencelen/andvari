package io.silencelen.andvari.app

import io.silencelen.andvari.app.autofill.AppIdentityLookup
import io.silencelen.andvari.core.client.autofill.AppFillGate
import org.w3c.dom.Element
import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Security review 2026-10, A14 (F7): an `androidapp://<pkg>` login filled into whichever app held
 * that package name. The decision is core AppFillGate (table-tested there); this pins the digest the
 * binding is keyed on and the wiring: identity from PackageManager on the service side, the verdict
 * and the identity baked into the confirm PendingIntent's base intent (root cause G), credentials
 * released only after the confirm, nothing silent on an error, bindings device-local and cleared on
 * sign-out. What a JVM test cannot prove (the system's real flags / installer / signer answers and
 * package visibility on API 30+) is an owner device check.
 */
class A14AppFillGateTest {
    @Test
    fun theSignerDigestIsTheCurrentSignersSha256InStableOrder() {
        val a = byteArrayOf(1, 2, 3)
        val b = byteArrayOf(4, 5, 6)
        val one = AppIdentityLookup.signerDigest(listOf(a))
        assertEquals(64, one.length)
        assertEquals("039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81", one, "SHA-256 of 01 02 03, lowercase hex")
        assertEquals(AppIdentityLookup.signerDigest(listOf(a, b)), AppIdentityLookup.signerDigest(listOf(b, a)), "multiple signers: order-free")
        assertNotEquals(one, AppIdentityLookup.signerDigest(listOf(a, b)), "a second signer changes the identity")
    }

    private fun sourceFile(relative: String): File =
        listOf(File(relative), File("app-android/$relative")).firstOrNull { it.isFile }
            ?: error("could not locate $relative from ${File(".").absolutePath}")
    private fun src(name: String) = sourceFile("src/main/kotlin/io/silencelen/andvari/app/$name").readText()

    @Test
    fun aGatedLoginReleasesNothingUntilTheConfirm() {
        val builder = src("autofill/DatasetBuilder.kt")
        assertTrue(builder.contains("val appGate = appGateFor(context, form)"), "the verdict is computed once per request, service-side")
        assertTrue(builder.contains("if (appGate != null && appGate.verdict != AppFillGate.Verdict.SILENT)"), "a non-silent verdict builds the confirm row")
        val confirm = builder.substring(builder.indexOf("private fun confirmDataset("), builder.indexOf("// ---- no-match fallback row ----"))
        assertTrue(confirm.contains("b.setValue(f.id, null)"), "the confirm row carries no credential value")
        assertTrue(confirm.contains("AppFillBinding.bake(FillBinding.bake(Intent(context, AppFillConfirmActivity::class.java), form), appGate, item.itemId)"))
        assertTrue(confirm.contains("b.setAuthentication(pi.intentSender)"))
    }

    @Test
    fun theConfirmActivityTrustsOnlyTheBakeAndTheLiveIdentity() {
        val activity = src("autofill/AppFillConfirmActivity.kt")
        assertTrue(activity.contains("val form = FillBinding.resolve(intent)"), "the baked form, never the host-delivered structure")
        assertTrue(activity.contains("val bake = AppFillBinding.resolve(intent)"))
        assertTrue(activity.contains("AppIdentityLookup.lookup(applicationContext, bake.identity.pkg)"), "the identity is re-read live")
        assertTrue(activity.contains("EXTRA_AUTHENTICATION_RESULT"))
        // A14 review N7: re-read at the TAP too, not only at onCreate, and refused if anything moved.
        val fill = activity.substring(activity.indexOf("private fun confirmAndFill("), activity.indexOf("override fun onWindowFocusChanged("))
        assertTrue(fill.contains("AppFillGate.unchangedSince(bake.identity, AppIdentityLookup.lookup(applicationContext, bake.identity.pkg))"),
            "the live signer and installer are re-read at the tap")
        // A14 review N7: the binding is remembered only when a fill is actually delivered.
        val delivered = fill.indexOf("if (dataset != null) {")
        val remember = fill.indexOf("AppSignerBindings.remember(applicationContext, bake.identity.pkg, digest)")
        assertTrue(delivered >= 0 && remember > delivered && remember < fill.indexOf("} else {", delivered), "remember only inside the delivered branch")
        assertEquals(1, Regex("AppSignerBindings\\.remember\\(").findAll(activity).count(), "one place remembers a binding")
    }

    @Test
    fun theConfirmResistsOverlaysAndATapAtTheWrongMoment() {
        // A14 review N6: touches through an overlay are dropped, other apps' overlays are hidden (API 31+), and the
        // button only accepts a tap a moment after the window gained focus.
        val activity = src("autofill/AppFillConfirmActivity.kt")
        assertTrue(activity.contains("window.decorView.filterTouchesWhenObscured = true"))
        assertTrue(activity.contains("view.filterTouchesWhenObscured = true"), "the compose host view filters too")
        assertTrue(activity.contains("if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)"))
        assertTrue(Regex("ARM_DELAY_MS = (\\d+)L").find(activity)!!.groupValues[1].toLong() in 400L..1000L, "about half a second")
        assertTrue(activity.contains("armed = armed.value,") && activity.contains("Button(onClick = onFill, enabled = armed,"), "the button is disabled until armed")
        val fill = activity.substring(activity.indexOf("private fun confirmAndFill("), activity.indexOf("override fun onWindowFocusChanged("))
        assertTrue(fill.contains("if (!armed.value) return"), "the state layer refuses an unarmed tap too")
        val focus = activity.substring(activity.indexOf("override fun onWindowFocusChanged("))
        assertTrue(focus.contains("armed.value = false"), "losing focus (an overlay, a dialog) disarms")
        assertTrue(focus.contains("handler.postDelayed(arm, ARM_DELAY_MS)"))
        val manifest = sourceFile("src/main/AndroidManifest.xml").readText()
        assertTrue(manifest.contains("android.permission.HIDE_OVERLAY_WINDOWS"), "setHideOverlayWindows needs its (normal) permission")
    }

    @Test
    fun theConfirmShowsSafeOneLineTextAndNamesTheLogin() {
        // A14 review N2: the label is the app's own choice. It is made safe for presentation, escaped onto one line, and
        // rendered maxLines=1 with an ellipsis; the installer line names its package and system status; the card names the
        // item and username it would release. The "signer changed" card is the same card.
        val lookup = src("autofill/AppIdentityLookup.kt")
        assertTrue(lookup.contains("TextUtils.makeSafeForPresentation("), "labels go through the platform's presentation sanitizer")
        assertTrue(lookup.contains("TextUtils.SAFE_STRING_FLAG_SINGLE_LINE"))
        val activity = src("autofill/AppFillConfirmActivity.kt")
        val card = activity.substring(activity.indexOf("private fun ConfirmCard("))
        assertTrue(card.contains("AppFillGate.oneLine(id.label)"), "the label is escaped onto one bounded line")
        assertTrue(card.contains("AppFillGate.installerLine(id.installer, bake.installerLabel, id.installerSystem)"), "the installer's package and system flag")
        assertTrue(card.contains("AppFillGate.oneLine(login.name)") && card.contains("AppFillGate.oneLine(login.username)"), "the login it would release")
        val singleLine = Regex("maxLines = 1, overflow = TextOverflow.Ellipsis").findAll(card).count()
        assertTrue(singleLine >= 4, "label, installer label, item name and username are single-line ($singleLine)")
        assertTrue(!card.contains("Fill a login into \$app"), "the title no longer embeds the attacker-chosen label")
    }

    private fun xml(relative: String) = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(sourceFile(relative))

    @Test
    fun theRequestingAppAndItsInstallerAreVisibleOnApi30() {
        // A14 lead finding: the autofill framework grants andvari no visibility of the requesting app, and the manifest
        // queried browsers only, so on API 30+ every lookup threw and every app fill confirmed with nothing remembered.
        val doc = xml("src/main/AndroidManifest.xml")
        val queries = doc.getElementsByTagName("queries").item(0) as Element
        val intents = queries.getElementsByTagName("intent")
        val launcher = (0 until intents.length).map { intents.item(it) as Element }.any { intent ->
            val action = intent.getElementsByTagName("action")
            val category = intent.getElementsByTagName("category")
            (0 until action.length).any { (action.item(it) as Element).getAttribute("android:name") == "android.intent.action.MAIN" } &&
                (0 until category.length).any { (category.item(it) as Element).getAttribute("android:name") == "android.intent.category.LAUNCHER" }
        }
        assertTrue(launcher, "<queries> has the MAIN/LAUNCHER intent")
        val pkgs = queries.getElementsByTagName("package")
        assertTrue((0 until pkgs.length).any { (pkgs.item(it) as Element).getAttribute("android:name") == AppFillGate.PLAY_INSTALLER },
            "the Play installer is queried by name, so N1 can read its system flag")
        val perms = doc.getElementsByTagName("uses-permission")
        assertTrue((0 until perms.length).none { (perms.item(it) as Element).getAttribute("android:name") == "android.permission.QUERY_ALL_PACKAGES" })
        val lookup = src("autofill/AppIdentityLookup.kt")
        assertTrue(lookup.contains("installerSystem = installerSystemOf(pm, installer)"), "the installer's own system flag is read (N1)")
    }

    @Test
    fun bindingsNeverLeaveTheDevice() {
        // A14 review N5: device-local means out of cloud backup AND device-to-device transfer (which runs even with
        // allowBackup=false on API 31+), and out of the legacy full-backup rules.
        val rules = xml("src/main/res/xml/data_extraction_rules.xml")
        for (section in listOf("cloud-backup", "device-transfer")) {
            val el = rules.getElementsByTagName(section).item(0) as Element
            val ex = el.getElementsByTagName("exclude")
            assertTrue((0 until ex.length).map { ex.item(it) as Element }.any { it.getAttribute("domain") == "sharedpref" && it.getAttribute("path") == "andvari_app_signer_bindings.xml" },
                "$section excludes the app signer bindings")
        }
        val legacy = xml("src/main/res/xml/backup_rules.xml").getElementsByTagName("exclude")
        assertTrue((0 until legacy.length).map { legacy.item(it) as Element }.any { it.getAttribute("domain") == "sharedpref" && it.getAttribute("path") == "andvari_app_signer_bindings.xml" },
            "full-backup-content excludes the app signer bindings")
    }

    @Test
    fun bindingsAreDeviceLocalAndClearedWheneverTheSessionEnds() {
        val vm = src("AndvariViewModel.kt")
        val signOut = vm.substring(vm.indexOf("fun signOut(reason: String? = null) {"), vm.indexOf("pendingBackupRequest = null", vm.indexOf("fun signOut(reason: String? = null) {")))
        assertTrue(signOut.contains("AppSignerBindings.clearAll(appContext)"), "sign-out forgets which apps this member confirmed")
        // A14 review N5: a session also ends without signOut - a definitive 401 on unlock (store.clear()), a revocation
        // purge (OfflineData.purgeRevoked -> store.clear()), a refused refresh (updateTokens(null) -> clear()), a server
        // switch (clearSessionTokens) - and another account saved over this one. Every one of them goes through the store.
        val store = src("Session.kt")
        for (fn in listOf("fun clear() {", "fun clearSessionTokens() {", "fun save(s: Session) {")) {
            val body = store.substring(store.indexOf(fn), store.indexOf("\n    }", store.indexOf(fn)))
            assertTrue(body.contains("AppSignerBindings.clearAll(appContext)"), "$fn clears the app signer bindings")
        }
        val bindings = src("autofill/AppSignerBindings.kt")
        assertTrue(bindings.contains("getSharedPreferences(PREFS, Context.MODE_PRIVATE)"), "a plain device-local preference")
        assertTrue(bindings.contains("PREFS = \"andvari_app_signer_bindings\""), "the file the backup rules exclude")
        assertTrue(!bindings.contains("AndvariApi") && !bindings.contains("SyncEngine"), "never on the wire")
    }
}
