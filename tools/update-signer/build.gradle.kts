plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.shadow)
    application
}

kotlin {
    jvmToolchain(17)
}

// OFFLINE TOOL (H2, design 2026-07-13-signed-updates §G) — the release-signing private key lives on
// the OWNER'S WORKSTATION and never touches a server. NO HTTP client on the classpath.
dependencies {
    implementation(project(":core")) {
        exclude(group = "io.ktor")
        exclude(group = "com.squareup.okhttp3")
    }
    implementation(libs.lazysodium.java)
    implementation(libs.jna)
    testImplementation(libs.kotlin.test)
}

application {
    mainClass.set("io.silencelen.andvari.updatesigner.MainKt")
}

// Build a self-contained jar (runs on the workstation with only a JRE 17+):
//   ./gradlew :tools:update-signer:shadowJar
//   → tools/update-signer/build/libs/andvari-update-signer.jar  (java -jar, no deps)
tasks.shadowJar {
    archiveBaseName.set("andvari-update-signer")
    archiveClassifier.set("")
    mergeServiceFiles()
}
