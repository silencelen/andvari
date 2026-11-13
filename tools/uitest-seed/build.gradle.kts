plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.shadow)
    application
}

kotlin {
    jvmToolchain(17)
}

// TEST TOOL, never shipped: seeds a throwaway server for the iOS UI tests (.github/workflows/ios-uitest.yml).
// It is an ordinary client: it enrolls through the bootstrap invite and saves items through the sync engine.
dependencies {
    implementation(project(":core"))
    implementation(libs.lazysodium.java)
    implementation(libs.jna)
    implementation(libs.ktor.client.java)
    implementation(libs.kotlinx.serialization.json)
}

application {
    mainClass.set("io.silencelen.andvari.uitestseed.MainKt")
}

tasks.shadowJar {
    archiveBaseName.set("andvari-uitest-seed")
    archiveClassifier.set("")
    mergeServiceFiles()
}
