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
}

compose.desktop {
    application {
        mainClass = "io.silencelen.andvari.desktop.MainKt"
        nativeDistributions {
            targetFormats(TargetFormat.Msi, TargetFormat.Deb)
            packageName = "andvari"
            packageVersion = "0.17.0"
            description = "andvari password manager"
            vendor = "silencelen"
            // JDK modules the jlink runtime image must include — Compose's default set is
            // minimal and omits these, so without this the bundled runtime crashes at
            // startup: java.net.http (ktor Java HTTP engine), java.sql (sqlite-jdbc),
            // jdk.unsupported (JNA/lazysodium sun.misc.Unsafe). List from
            // `gradlew :app-desktop:suggestRuntimeModules`. Applies to BOTH .msi and .deb.
            // jdk.accessibility (design 2026-07-13 platform-fit §3): without it the minimized
            // runtime image CANNOT load the Java Access Bridge, so Windows screen-reader support is
            // broken at the packaging layer even after the user runs `jabswitch /enable`. Shipping a
            // runtime that can't load the bridge is strictly wrong; see docs/accessibility.md.
            modules("java.instrument", "java.management", "java.net.http", "java.sql", "jdk.unsupported", "jdk.accessibility")
            windows {
                // STABLE across releases → re-running a newer installer upgrades in
                // place instead of installing a second copy. NEVER change this.
                upgradeUuid = "5f2b9a1c-4d3e-4c7a-9b8f-1a2c3d4e5f60"
                menuGroup = "andvari"
                shortcut = true
            }
        }
    }
}
