plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.androidLibrary)
}

kotlin {
    jvmToolchain(17)

    jvm()
    androidTarget()

    sourceSets {
        commonMain.dependencies {
            api(libs.kotlinx.coroutines.core)
            api(libs.kotlinx.serialization.json)
            api(libs.kotlinx.datetime)
            // Client networking (the HTTP engine is provided per platform).
            api(libs.ktor.client.core)
            implementation(libs.ktor.client.content.negotiation)
            implementation(libs.ktor.serialization.kotlinx.json)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
        // The lazysodium adapter is one file compiled into both JVM-family targets;
        // the com.goterl.lazysodium API is identical across the two artifacts.
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
        jvmTest.dependencies {
            implementation(libs.ktor.client.java)
            implementation(libs.ktor.client.mock) // fake engine for AndvariApi refresh tests
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
tasks.withType<Test>().configureEach {
    systemProperty(
        "andvari.vectors.dir",
        rootProject.projectDir.resolve("spec/test-vectors").absolutePath,
    )
    inputs.dir(rootProject.projectDir.resolve("spec/test-vectors"))
        .withPropertyName("andvariTestVectors")
        .withPathSensitivity(PathSensitivity.RELATIVE)
}
