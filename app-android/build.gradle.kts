import java.util.Properties

// Release signing: keystore.properties from ~/.andvari,
// env-overridable; absent → release builds UNSIGNED (CI-safe, and P2 ships debug first).
val keystorePropsFile = file(
    System.getenv("ANDVARI_KEYSTORE_PROPERTIES") ?: "${System.getProperty("user.home")}/.andvari/keystore.properties",
)
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.kotlinAndroid)
    alias(libs.plugins.kotlinCompose)
    alias(libs.plugins.kotlinSerialization)
}

android {
    namespace = "com.silencelen.andvari"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.silencelen.andvari"
        minSdk = 29
        targetSdk = 35
        versionCode = (System.getenv("ANDVARI_VERSIONCODE") ?: "1").toInt()
        versionName = "0.27.0"
        // lazysodium-android bundles native .so — limit to the phone's ABI.
        ndk { abiFilters += "arm64-v8a" }
        // H94: the instrumented vector run (src/androidTest) needs a runner. Nothing else in the
        // module uses instrumentation, and declaring it costs the app APK nothing — the runner and
        // the test classes live in the SEPARATE androidTest APK.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    sourceSets {
        // H94: the instrumented crypto test is graded against spec/test-vectors — the SAME files
        // core's jvmTest, web's vitest and the extension's node suite read. They are mounted as
        // the TEST apk's assets straight out of the spec directory rather than copied in: a copy
        // is a second corpus that drifts, and the whole point of the corpus is that every
        // implementation answers to one set of bytes.
        getByName("androidTest") { assets.srcDir(rootProject.file("spec/test-vectors")) }
    }

    signingConfigs {
        // Checked-in debug key (devstore lesson: AGP's per-machine default debug key
        // breaks update continuity across build hosts).
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
        if (keystoreProps.isNotEmpty()) {
            create("release") {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = if (keystoreProps.isNotEmpty()) signingConfigs.getByName("release") else null
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { compose = true }
}

dependencies {
    implementation(project(":core"))
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.graphics)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons.extended)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.autofill)
    // Quick unlock (design 2026-07-10 §2): BiometricPrompt + BiometricManager. Pulls in
    // androidx.fragment transitively, so the unlock/autofill activities host it via FragmentActivity.
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.browser)
    // Force fragment 1.8.5 over the 1.2.5 that biometric drags in: 1.2.5's FragmentActivity enforces
    // the legacy 16-bit requestCode check and CRASHES every Activity-Result launch (the import
    // "Choose file" picker, MainActivity.kt) under activity 1.9.3's registry. See libs.versions.toml.
    implementation(libs.androidx.fragment)
    implementation(libs.kotlinx.coroutines.core)
    // Gate-2 §4.2 originKey byte-parity pins (OriginNamespaceTest) — pure-JVM, runs under
    // testDebugUnitTest. Explicit JUnit4 provider: this is the first AGP module with unit tests,
    // and AGP's testDebugUnitTest runs JUnit4 natively (no useJUnitPlatform wiring needed).
    testImplementation(kotlin("test-junit"))
    // H94 — the INSTRUMENTED vector run: the phone's crypto actual is lazysodium-android with its
    // own bundled libsodium .so, and until this existed no test ever executed it; the JVM suites
    // grade lazysodium-java over a different native binary and were standing in for it by
    // assumption. Versions are literals here rather than catalog refs because gradle/libs.versions
    // .toml is outside this module's remit in the 0.27.0 remediation — fold them in with H101's
    // catalog read of the lazysodium-android coordinate.
    androidTestImplementation(project(":core"))
    androidTestImplementation(kotlin("test-junit"))
    androidTestImplementation("androidx.test:runner:1.6.2")
    // The androidTest graph is smaller than the app's and would otherwise settle androidx.core a
    // patch LOWER (1.13.0) than the app resolves (1.13.1) — two versions of the same library
    // across the two APKs, for no reason anyone chose. Pin it to what the app actually ships.
    androidTestImplementation("androidx.core:core:1.13.1")
}
