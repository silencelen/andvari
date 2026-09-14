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
    // §4.2 namespacing gate tests (originKey byte-parity pins, adoption one-shot, scoped purges).
    testImplementation(libs.kotlin.test)
}

compose.desktop {
    application {
        mainClass = "io.silencelen.andvari.desktop.MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Deb)
            packageName = "andvari"
            packageVersion = "0.27.0"
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
            // H138: the source moved to assets/brand/andvari-mark.svg (icons/andvari.svg is now a
            // copy of it) and onto the wordmark geometry, so this mark is byte-for-byte the one
            // the web favicon, the extension toolbar and the phone launcher show. Regenerate with
            // scripts/gen-brand-icons.sh; nothing under icons/ is hand-edited.
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
