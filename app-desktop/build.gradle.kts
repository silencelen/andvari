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
            packageVersion = "0.9.0"
            description = "andvari password manager"
            vendor = "silencelen"
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
