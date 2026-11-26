plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.androidLibrary)
}

kotlin {
    jvmToolchain(17)

    jvm()
    androidTarget()

    // iOS is built on macOS only. libsodium comes from scripts/ci/build-libsodium-ios.sh, which
    // compiles the official release at a pinned hash into core/build/libsodium/<target>.
    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        val sodium = layout.buildDirectory.dir("libsodium/${target.name}").get().asFile
        target.compilations.getByName("main").cinterops.create("sodium") {
            definitionFile.set(file("src/nativeInterop/cinterop/sodium.def"))
            includeDirs(sodium.resolve("include"))
            extraOpts("-libraryPath", sodium.resolve("lib").path)
        }
        target.compilations.getByName("main").cinterops.create("sqlite3") {
            definitionFile.set(file("src/nativeInterop/cinterop/sqlite3.def"))
        }
        target.binaries.framework {
            baseName = "AndvariCore"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
            api(libs.kotlinx.datetime)
            // Client networking (the HTTP engine is provided per platform).
            implementation(libs.kotlinx.atomicfu) // multiplatform locks
            api(libs.ktor.client.core)
            implementation(libs.ktor.client.content.negotiation)
            implementation(libs.ktor.serialization.kotlinx.json)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.ktor.client.mock) // fake engine for AndvariApi tests
        }
        // The lazysodium adapter is one file compiled into both JVM-family targets;
        // the com.goterl.lazysodium API is identical across the two artifacts.
        iosMain.dependencies {
            api(libs.ktor.client.darwin)
        }
        jvmMain {
            kotlin.srcDir("src/jvmShared/kotlin")
            dependencies {
                implementation(libs.lazysodium.java)
                implementation(libs.jna)
                api(libs.ktor.client.java)
                // Durable client cache (spec 02 §8) — same driver the server proves.
                implementation(libs.sqlite.jdbc)
            }
        }
        jvmTest {
            // The zero-key tripwire (test machinery, never shipped): see gradle/zero-key-tripwire.gradle.kts.
            kotlin.srcDir("src/jvmTripwire/kotlin")
            resources.srcDir("src/jvmTripwire/resources")
            dependencies {
                implementation(libs.ktor.client.java)
            }
        }
        androidMain {
            kotlin.srcDir("src/jvmShared/kotlin")
            dependencies {
                // lazysodium-android pulls JNA as a plain .jar; Android needs the .aar
                // (it carries the native libs). Exclude the transitive jar to avoid a
                // duplicate-class clash, then add the aar explicitly. String coordinates
                // because the KMP source-set DSL doesn't accept a catalog provider with a
                // configure lambda — but the VERSIONS are read from the catalog, never
                // retyped (audit H101): the JVM target and the server take `libs.jna` /
                // `libs.lazysodium.java` from the same file, and the one crypto adapter
                // (LazySodiumCryptoProvider.kt) is compiled against both artifacts, so a
                // catalog bump that left a literal behind would ship the phone a different
                // libsodium than the JVM clients, surfacing only as an UnsatisfiedLinkError
                // on the device.
                implementation("com.goterl:lazysodium-android:${libs.versions.lazysodium.android.get()}") {
                    exclude(group = "net.java.dev.jna", module = "jna")
                    // 5.2.0 declares androidx.core, which no class of the library refers to: excluded, so the
                    // library's update moves no other dependency (every classpath differs from 5.1.0's in the
                    // library's own line only).
                    exclude(group = "androidx.core")
                }
                implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")
                api(libs.ktor.client.okhttp)
            }
        }
    }
}

android {
    namespace = "io.silencelen.andvari.core"
    compileSdk = 35
    defaultConfig {
        minSdk = 29
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

// Vector-driven tests read the normative fixtures from spec/test-vectors. The dir
// must be a declared input or Gradle marks tests UP-TO-DATE when vectors change.
// The simulator passes SIMCTL_CHILD_X to the test process as X. It can read the host's files.
tasks.withType<org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest>().configureEach {
    environment("SIMCTL_CHILD_ANDVARI_VECTORS_DIR", rootProject.projectDir.resolve("spec/test-vectors").absolutePath)
    inputs.dir(rootProject.projectDir.resolve("spec/test-vectors"))
        .withPropertyName("andvariTestVectors")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}

// The tripwire for keys used after a lock: the test JVM's crypto provider
// records every operation under an all-zero key, and the floor every refusal, and the suite fails at its end on any line
// no test asked for. Core's Android unit tests (commonTest run again on the Android variant) are not watched.
extra["zeroKeyTripwireTasks"] = listOf("jvmTest")
apply(from = rootProject.file("gradle/zero-key-tripwire.gradle.kts"))

// The shared code's test server (FakeInstance, BearerTransport and the other helpers of commonTest), for the apps' unit
// tests: the apps prove their screens over the real engine against the same in-memory server the shared code's own tests
// use. Each configuration below carries the classes of one TEST compilation of this module, as a jar, and nothing else:
// no dependency (the consumer brings kotlin-test itself; ktor-client-mock is not carried), no resource, and none of
// core's main classes (the consumer has those from its ordinary dependency on :core, in the variant it runs).
// The apps take them on their unit-test class paths only, never on a main or release one.
// - testServerJvmElements: jvmTest's classes (commonTest + jvmTest), compiled against core's JVM variant; for the
//   desktop. The zero-key tripwire, which jvmTest compiles in as well, is left out: the desktop compiles its own copy.
// - testServerAndroidDebugElements / testServerAndroidReleaseElements: the classes of core's own Android unit-test
//   compilation of that build type (commonTest + androidUnitTest), compiled against core's Android variant of that build
//   type; for the Android app's unit tests of the same build type. Not the JVM jar: a class of the shared code's tests
//   that calls an `internal` member of core calls it by a name that carries the module's name, which differs between
//   core's JVM and Android variants, so the JVM-compiled server does not link against the Android variant.
// Each has a capability of its own (as Gradle's test fixtures have), so it never stands in for core itself.
val testServerJvmElements: Configuration by configurations.creating {
    isCanBeConsumed = true
    isCanBeResolved = false
    outgoing.capability("io.silencelen.andvari:core-test-server-jvm:1")
}
val testServerAndroidDebugElements: Configuration by configurations.creating {
    isCanBeConsumed = true
    isCanBeResolved = false
    outgoing.capability("io.silencelen.andvari:core-test-server-android-debug:1")
}
val testServerAndroidReleaseElements: Configuration by configurations.creating {
    isCanBeConsumed = true
    isCanBeResolved = false
    outgoing.capability("io.silencelen.andvari:core-test-server-android-release:1")
}
val testServerJvmJar by tasks.registering(Jar::class) {
    archiveBaseName.set("core-test-server-jvm")
    destinationDirectory.set(layout.buildDirectory.dir("test-server"))
    from(kotlin.jvm().compilations.getByName("test").output.classesDirs)
    exclude("io/silencelen/andvari/tripwire/**")
}
artifacts.add(testServerJvmElements.name, testServerJvmJar)
kotlin.androidTarget().compilations.all {
    val compilation = this
    val (buildType, elements) = when (compilation.name) {
        "debugUnitTest" -> "debug" to testServerAndroidDebugElements
        "releaseUnitTest" -> "release" to testServerAndroidReleaseElements
        else -> return@all
    }
    val jar = tasks.register<Jar>("testServerAndroid${buildType.replaceFirstChar { it.uppercase() }}Jar") {
        archiveBaseName.set("core-test-server-android-$buildType")
        destinationDirectory.set(layout.buildDirectory.dir("test-server"))
        from(compilation.output.classesDirs)
    }
    artifacts.add(elements.name, jar)
}

tasks.withType<Test>().configureEach {
    systemProperty(
        "andvari.vectors.dir",
        rootProject.projectDir.resolve("spec/test-vectors").absolutePath,
    )
    inputs.dir(rootProject.projectDir.resolve("spec/test-vectors"))
        .withPropertyName("andvariTestVectors")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}
