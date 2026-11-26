plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlinSerialization)
}

kotlin {
    jvmToolchain(17)
}

// The hostile-server harness (design §17 "Flow conformance", §18.2; spec 05 T1): a proxy between the real client
// engine and the real server that lies, withholds, replays, forks, swaps and races, with one test per thing the design
// says a client must do in response. Tests only: nothing here ships, and nothing here patches the engine or the server.
dependencies {
    // The real server in its test mode, the mail sink, the test clock and a device's engine, as the journeys use them.
    testImplementation(testFixtures(project(":tools:andvari-cli")))
    testImplementation(project(":tools:andvari-cli"))
    testImplementation(project(":core"))
    testImplementation(libs.kotlin.test)
    testImplementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.kotlinx.serialization.json)
    testImplementation(libs.ktor.client.java)
}

// A few scenarios play the one adversary a proxy cannot be on its own: T1 as the OPERATOR (two cards at one position,
// a card that changes `kind`), and a holder of the account's UVK (R35). Both need a key the engine keeps internal, so
// this module compiles as a friend of :core, exactly as :tools:andvari-cli does. The README lists every symbol used.
val coreJvmJar = project(":core").layout.buildDirectory.file("libs/core-jvm.jar")
val coreJvmClasses = project(":core").layout.buildDirectory.dir("classes/kotlin/jvm/main")
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    compilerOptions.freeCompilerArgs.add(
        "-Xfriend-paths=${coreJvmJar.get().asFile.absolutePath},${coreJvmClasses.get().asFile.absolutePath}",
    )
}

tasks.test {
    // Each scenario starts its own server and derives Argon2 keys at the production parameters.
    maxHeapSize = "1g"
    maxParallelForks = 2
    testLogging { events("passed", "failed", "skipped"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

// The zero-key tripwire on the bench: test machinery, in the test source set only.
kotlin.sourceSets.getByName("test") {
    kotlin.srcDir(rootProject.file("core/src/jvmTripwire/kotlin"))
    resources.srcDir(rootProject.file("core/src/jvmTripwire/resources"))
}
apply(from = rootProject.file("gradle/zero-key-tripwire.gradle.kts"))
