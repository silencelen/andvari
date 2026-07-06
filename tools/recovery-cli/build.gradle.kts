plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.shadow)
    application
}

kotlin {
    jvmToolchain(17)
}

// OFFLINE TOOL — deliberately NO HTTP client on the classpath (spec 04 §5).
// Only :core (crypto) + lazysodium + zxing (QR rendering). A network dependency
// creeping in here is a review-blocking regression.
dependencies {
    implementation(project(":core"))
    implementation(libs.lazysodium.java)
    implementation(libs.jna)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.zxing.core)
    testImplementation(libs.kotlin.test)
}

application {
    mainClass.set("io.silencelen.andvari.recovery.MainKt")
}

tasks.shadowJar {
    archiveBaseName.set("andvari-recovery-cli")
    archiveClassifier.set("")
}
