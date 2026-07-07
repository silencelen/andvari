plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.shadow)
    application
}

kotlin {
    jvmToolchain(17)
}

// OFFLINE TOOL — deliberately NO HTTP client on the classpath (spec 07 §3: "same
// discipline as recovery-cli"). Only :core (crypto + the Backup reference impl) +
// lazysodium. A network dependency creeping in here is a review-blocking regression.
dependencies {
    // Exclude the network stack that :core carries for the online clients — the
    // offline tool must have NO HTTP client on its classpath (enforced by test).
    implementation(project(":core")) {
        exclude(group = "io.ktor")
        exclude(group = "com.squareup.okhttp3")
    }
    implementation(libs.lazysodium.java)
    implementation(libs.jna)
    implementation(libs.kotlinx.serialization.json)
    testImplementation(libs.kotlin.test)
}

application {
    mainClass.set("io.silencelen.andvari.backup.MainKt")
}

// The reader of record for `.andvari` backups until client restore ships (spec 07 §3).
// Runs anywhere with a JRE 17+ — no gradle, no network, no repo checkout:
//   flock /tmp/andvari-gradle.lock ./gradlew :tools:backup-cli:shadowJar
//   → tools/backup-cli/build/libs/andvari-backup-cli.jar   (java -jar, no deps)
// lazysodium/JNA natives ride inside the jar as plain resources (JNA self-extracts).
tasks.shadowJar {
    archiveBaseName.set("andvari-backup-cli")
    archiveClassifier.set("")
    mergeServiceFiles() // same as :server — keep ServiceLoader metadata intact when deps merge
}
