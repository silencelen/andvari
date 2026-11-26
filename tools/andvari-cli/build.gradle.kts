plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.shadow)
    application
    // The bootstrap the journeys use (the real server in test mode, the mail sink, the test clock, a device's engine)
    // is published as test fixtures, so another module (the hostile-server harness) depends on it instead of copying:
    //   testImplementation(testFixtures(project(":tools:andvari-cli")))
    `java-test-fixtures`
}

kotlin {
    jvmToolchain(17)
}

// The headless client (design §9.5, §12, §14.1, §18, the CLI): the engine of :core over the JVM's HTTP client.
dependencies {
    implementation(project(":core"))
    implementation(libs.lazysodium.java)
    implementation(libs.jna)
    implementation(libs.ktor.client.java)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.core)
    // The server's logging backend, so ktor's SLF4J calls find a provider (approved by the owner on 2026-11-15). Its
    // configuration (andvari-cli-logback.xml, chosen in main) keeps standard output for the command alone.
    runtimeOnly(libs.logback.classic)

    // The fixtures run the real server in its test mode on 127.0.0.1 (design §7.1, §9.5).
    testFixturesApi(project(":core"))
    testFixturesApi(project(":server"))
    testFixturesApi(libs.kotlin.test)
    testFixturesApi(libs.kotlinx.coroutines.core)
    testFixturesApi(libs.kotlinx.serialization.json)
    testFixturesImplementation(libs.ktor.server.core)
    testFixturesImplementation(libs.ktor.server.netty)
    testFixturesImplementation(libs.ktor.client.java)
    // Journey 7 runs the offline tool's `assist` and `rotate` as the operator would, in its own process.
    testFixturesImplementation(project(":tools:recovery-cli"))

    testImplementation(libs.kotlin.test)
}

// The tool, its tests and its fixtures take everything from the engine's public calls: this module is no friend of
// :core, and InternalAccessTest reads the shipped classes to pin that they reach nothing internal of it.

application {
    mainClass.set("io.silencelen.andvari.cli.MainKt")
    applicationName = "andvari-cli"
}

tasks.test {
    // The journeys start a server per test class and derive Argon2 keys at the production parameters.
    maxHeapSize = "1g"
    // LoggingTest runs the tool in a JVM of its own on exactly what the distribution ships (the main runtime classpath).
    val shipped = sourceSets.main.get().runtimeClasspath
    inputs.files(shipped)
    jvmArgumentProviders.add(CommandLineArgumentProvider { listOf("-Dandvari.cli.runtimeClasspath=${shipped.asPath}") })
    // SetupTestOperatorTest runs `andvari setup --test --cli <the installed tool>`: the distribution installDist makes,
    // started by its own launcher script, on the toolchain's Java.
    dependsOn(tasks.installDist)
    val installed = layout.buildDirectory.file("install/andvari-cli/bin/andvari-cli")
    jvmArgumentProviders.add(CommandLineArgumentProvider { listOf("-Dandvari.cli.installed=${installed.get().asFile.absolutePath}") })
    environment("JAVA_HOME", javaLauncher.get().metadata.installationPath.asFile.absolutePath)
    testLogging { events("passed", "failed", "skipped"); exceptionFormat = org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL }
}

tasks.shadowJar {
    archiveBaseName.set("andvari-cli")
    archiveClassifier.set("")
    mergeServiceFiles()
}

// The zero-key tripwire on this module's tests: test machinery, in the test source set only
// (not in the test fixtures the hostile-server bench reuses; that module adds its own).
kotlin.sourceSets.getByName("test") {
    kotlin.srcDir(rootProject.file("core/src/jvmTripwire/kotlin"))
    resources.srcDir(rootProject.file("core/src/jvmTripwire/resources"))
}
apply(from = rootProject.file("gradle/zero-key-tripwire.gradle.kts"))
