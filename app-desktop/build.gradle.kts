import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.composeMultiplatform)
    alias(libs.plugins.kotlinCompose)
    alias(libs.plugins.kotlinSerialization)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    implementation(compose.desktop.currentOs)
    implementation(compose.material3)
    implementation(compose.materialIconsExtended)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.ktor.client.java) // the JVM HTTP engine for AndvariApi
    // The QR codes of the new path (the kit document, a device link, a connect link): onboarding and trust design
    // §0.3 "byte mode at error-correction level M". The catalog's encoder, the one recovery-cli already uses.
    implementation(libs.zxing.core)
    // The kept session is wrapped by the operating system's key store for this account
    // (Windows data protection; the Linux desktop's secret service through libsecret). Approved by the owner on
    // 2026-11-15 for that wrap and nothing else. One JNA version in the whole project: the catalog's `jna`, the one
    // core's libsodium binding already runs on; `jna-platform` (DPAPI's Crypt32Util) takes the same version.
    // The owner's decision of 2026-11-16 adds one use of the same `jna`, no new dependency: Windows'
    // SetWindowDisplayAffinity, which hides the app's windows from screen capture (ScreenCapture.kt).
    implementation(libs.jna)
    implementation(libs.jna.platform)
    // §4.2 namespacing gate tests (originKey byte-parity pins, adoption one-shot, scoped purges).
    testImplementation(libs.kotlin.test)
    // The shared code's own test server (FakeInstance and the helpers beside it, compiled against core's JVM variant),
    // so the tests can walk the real engine against it: on the test class paths only, never in the distribution.
    testImplementation(project(path = ":core", configuration = "testServerJvmElements"))
}

// The zero-key tripwire on this module's tests: test machinery, in the test source set only.
kotlin.sourceSets.getByName("test") {
    kotlin.srcDir(rootProject.file("core/src/jvmTripwire/kotlin"))
    resources.srcDir(rootProject.file("core/src/jvmTripwire/resources"))
}
apply(from = rootProject.file("gradle/zero-key-tripwire.gradle.kts"))

// The approved wording file, for a run that has one: its path in the environment variable ANDVARI_APPROVED_WORDING_FILE
// reaches the tests as the system property andvari.approvedWordingFile, and ApprovedCopyTest then checks every string
// the desktop carries against it. Without the variable that check is left out.
tasks.withType<Test>().configureEach {
    System.getenv("ANDVARI_APPROVED_WORDING_FILE")?.takeIf { it.isNotBlank() }?.let { systemProperty("andvari.approvedWordingFile", it) }
}

// The store-build constants of the public instance (onboarding and trust design §0.3) come from
// spec/public-instance.json, the one in-repo source ("every app's build reads this file"), as a small generated Kotlin
// object. A value that starts with "PLACEHOLDER:" does not exist yet: the app then bakes no public instance (and so
// offers no "Create an account on andvari"), and no installer can be made (checkStoreConstants, below).
val publicInstanceSpec: File = rootProject.file("spec/public-instance.json")
val generatedConstantsDir: File = layout.buildDirectory.dir("generated/andvariConstants/kotlin").get().asFile

fun readPublicInstance(): Map<String, String> {
    @Suppress("UNCHECKED_CAST")
    val root = groovy.json.JsonSlurper().parse(publicInstanceSpec) as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val pi = root["PUBLIC_INSTANCE"] as Map<String, Any?>
    return mapOf(
        "origin" to pi["origin"].toString(),
        "instanceId" to pi["instanceId"].toString(),
        "card0Hash" to pi["card0Hash"].toString(),
        "kind" to pi["kind"].toString(),
        "name" to pi["name"].toString(),
        "joinBase" to root["joinBase"].toString(),
    )
}

val generateBuildConstants = tasks.register("generateAndvariBuildConstants") {
    inputs.file(publicInstanceSpec)
    outputs.dir(generatedConstantsDir)
    doLast {
        val v = readPublicInstance()
        fun lit(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$") + "\""
        val baked = listOf("origin", "instanceId", "card0Hash", "kind").none { v.getValue(it).startsWith("PLACEHOLDER:") }
        val dir = File(generatedConstantsDir, "io/silencelen/andvari/desktop/trust")
        dir.mkdirs()
        File(dir, "BuildConstants.kt").writeText(
            """
            |// Generated from spec/public-instance.json by :app-desktop:generateAndvariBuildConstants. Do not edit.
            |package io.silencelen.andvari.desktop.trust
            |
            |internal object BuildConstants {
            |    /** False while any public-instance value is a placeholder: the build then bakes no public instance. */
            |    const val BAKES_PUBLIC_INSTANCE: Boolean = $baked
            |    const val PUBLIC_ORIGIN: String = ${lit(v.getValue("origin"))}
            |    const val PUBLIC_INSTANCE_ID: String = ${lit(v.getValue("instanceId"))}
            |    const val PUBLIC_CARD0_HASH: String = ${lit(v.getValue("card0Hash"))}
            |    const val PUBLIC_KIND: String = ${lit(v.getValue("kind"))}
            |    const val PUBLIC_NAME: String = ${lit(v.getValue("name"))}
            |    const val JOIN_BASE: String = ${lit(v.getValue("joinBase"))}
            |}
            |""".trimMargin(),
        )
    }
}
kotlin.sourceSets.getByName("main").kotlin.srcDir(generatedConstantsDir)
tasks.named("compileKotlin") { dependsOn(generateBuildConstants) }

// No installer or distributable is made while any store constant is a placeholder (spec/public-instance.json's own
// rule: "a store build MUST refuse to ship while any value starts with it"). Wired in front of every Compose packaging
// task (package*, create*Distributable, run*Distributable), so none can run past it; run
// `:app-desktop:checkStoreConstants` alone to see what it says. The desktop is not a store build (storeBuild = false),
// but it bakes the same public instance for the first screen, so the same rule holds.
val checkStoreConstants = tasks.register("checkStoreConstants") {
    inputs.file(publicInstanceSpec)
    doLast {
        val placeholders = readPublicInstance().filterValues { it.startsWith("PLACEHOLDER:") }.keys
        if (placeholders.isNotEmpty()) {
            throw GradleException("spec/public-instance.json still has placeholder values for $placeholders: no desktop installer may be made")
        }
    }
}
tasks.matching { it.name.startsWith("package") || it.name.contains("Distributable") }.configureEach { dependsOn(checkStoreConstants) }

// The JVM the app runs in, packaged and from the run task. The attach mechanism is off (no
// `jcmd <pid> GC.heap_dump` of an open vault by another program of the same user), and a crash leaves no core dump with
// the open keys. The error file (hs_err_pid*.log) goes inside the app's own directory only from the run task: jpackage
// expands $APPDIR, $BINDIR and $ROOTDIR in a launcher's options and HotSpot only %p, so the packaged app cannot name
// the per-user ~/.andvari-desktop there (a known gap).
val hardenedJvmArgs = listOf("-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash")
tasks.withType<JavaExec>().matching { it.name == "run" }.configureEach {
    jvmArgs("-XX:ErrorFile=" + File(File(System.getProperty("user.home"), ".andvari-desktop"), "hs_err_pid%p.log").path)
}

compose.desktop {
    application {
        mainClass = "io.silencelen.andvari.desktop.MainKt"
        jvmArgs += hardenedJvmArgs
        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Deb)
            packageName = "andvari"
            packageVersion = "0.30.0"
            description = "andvari password manager"
            vendor = "silencelen"
            // H130 — real package metadata. jpackage does NOT leave an unset field blank: it
            // substitutes its own literal defaults into the deb templates, so the 0.26.3 artifact
            // shipped `Maintainer: silencelen <Unknown>`, a .desktop entry reading
            // `Categories=Unknown`, and a copyright file declaring `License: Unknown` for a
            // GPL-3.0-or-later program. That last one is the reason this block is not cosmetic:
            // the .deb is the one artifact we sign and serve, and it was misstating the licence
            // the code actually ships under.
            //
            // `copyright` feeds template.copyright's `Copyright:` line. Owner's wording, kept
            // verbatim — do not "improve" it into an SPDX expression; LICENSING.md is the table
            // and the full text rides along in `licenseFile` below.
            copyright = "Copyright (c) 2026 silencelen"
            // `licenseFile` feeds jpackage --license-file, which BOTH targets consume: on Linux it
            // becomes template.copyright's `License:` body (replacing the literal "Unknown"), and on
            // Windows the MSI grows a licence page the installer must page past. The extra MSI page
            // is deliberate and owner-accepted — a GPL client that hides its licence at install time
            // is the worse trade. rootProject.file: the canonical GPLv3 text lives at the repo root
            // (LICENSING.md §"Full texts"), never a per-module copy that could drift.
            // Known and accepted: jpackage splices the file's bytes into template.copyright with
            // `Files.readString` and NO RFC-822 continuation indent, so the resulting copyright file
            // is not machine-parseable DEP-5. It is still the right trade — the field states the
            // real licence instead of "Unknown", and jpackage installs under /opt, which is not the
            // path Debian's copyright-format tooling inspects anyway.
            licenseFile.set(rootProject.file("LICENSE"))
            // JDK modules the jlink runtime image must include — Compose's default set is
            // minimal and omits these, so without this the bundled runtime crashes at
            // startup: java.net.http (ktor Java HTTP engine), java.sql (sqlite-jdbc),
            // jdk.unsupported (JNA/lazysodium sun.misc.Unsafe). List from
            // `gradlew :app-desktop:suggestRuntimeModules`. Applies to BOTH .msi and .deb.
            // jdk.accessibility (design 2026-07-13 platform-fit §3): without it the minimized
            // runtime image CANNOT load the Java Access Bridge, so Windows screen-reader support is
            // broken at the packaging layer even after the user runs `jabswitch /enable`. Shipping a
            // runtime that can't load the bridge is strictly wrong; see docs/accessibility.md.
            // jdk.zipfs (the jar/zip NIO FileSystemProvider): lazysodium's resource-loader reads the
            // bundled libsodium out of its jar via a `jar:` URI (Paths.get -> ResourceLoader
            // .getFileFromFileSystem). Without this module the provider is absent and the load dies
            // with `FileSystemNotFoundException: Provider "jar" not installed` — but ONLY on Windows
            // AND only when the install path contains a space (Program Files): the no-space path and
            // Linux take a stream-based branch that never needs it, which is exactly why it passed
            // every dev/build-folder run and the .deb, and failed for every real MSI install.
            modules("java.instrument", "java.management", "java.net.http", "java.sql", "jdk.unsupported", "jdk.accessibility", "jdk.zipfs")
            // The dark-background brand mark (gold ᛅ on #14120E) rendered per platform: .ico
            // carries every taskbar/Start size, the Linux .png feeds the .desktop entry. Without
            // these jpackage ships a blank generic icon (the app had none before).
            // The sources are under assets/brand/ (icons/andvari.svg is a copy of the small tile
            // andvari-mark.svg), so this mark is the one the web favicon, the extension toolbar
            // and the phone launcher show. Regenerate with scripts/gen-brand-icons.sh; nothing
            // under icons/ is hand-edited.
            windows {
                iconFile.set(project.file("icons/andvari.ico"))
                // STABLE across releases → re-running a newer installer upgrades in
                // place instead of installing a second copy. NEVER change this.
                upgradeUuid = "5f2b9a1c-4d3e-4c7a-9b8f-1a2c3d4e5f60"
                menuGroup = "andvari"
                shortcut = true
            }
            linux {
                iconFile.set(project.file("icons/andvari.png"))
                // jpackage composes the deb control line as `Maintainer: <vendor> <<debMaintainer>>`
                // — which is why the default produced `silencelen <Unknown>`. So this field carries
                // the ADDRESS ONLY: putting "silencelen <addr>" here would nest the display name
                // twice and lintian's maintainer-address-malformed would still fire. The address is
                // the owner's chosen fallback: SECURITY.md deliberately publishes no mailbox, and a
                // deb with no reachable maintainer is an error to every repo tool that reads it.
                debMaintainer = "silencelen@users.noreply.github.com"
                // Becomes DEPLOY_BUNDLE_CATEGORY → the freedesktop `Categories=` value in the
                // installed .desktop entry. "Unknown" is not a registered category, so GNOME/KDE
                // filed andvari under Other/Uncategorized (or hid it). Semicolon-TERMINATED because
                // Categories is a freedesktop string-list and the trailing `;` is part of the
                // grammar, not a typo.
                //
                // R21: `Utility` ALONE, not the `Utility;Security;` this first shipped as. Both
                // names are registered and the grammar was fine — the PAIRING was not. In the
                // freedesktop menu spec, `Security` is an Additional Category whose Related
                // Categories are `Settings;System`, so pairing it with `Utility` leaves
                // desktop-file-validate warning on exactly the entry the fix set out to make
                // clean. `Utility` is also the half that does the work (it files andvari under
                // Accessories); satisfying the table the other way would mean adding `System`,
                // which moves the app into System Tools menus for a tag no menu renders.
                menuGroup = "Utility;"
            }
        }
    }
}
