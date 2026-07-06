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
            }
        }
        jvmTest.dependencies {
            implementation(libs.ktor.client.java)
        }
        androidMain {
            kotlin.srcDir("src/jvmShared/kotlin")
            dependencies {
                implementation(libs.lazysodium.android)
                implementation("${libs.jna.get()}@aar")
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
