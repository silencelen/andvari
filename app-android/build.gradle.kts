import java.util.Properties

// Release signing (ledger/devstore pattern): keystore.properties from ~/.andvari,
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
        versionName = "0.3.0"
        // lazysodium-android bundles native .so — limit to the phone's ABI.
        ndk { abiFilters += "arm64-v8a" }
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
    implementation(libs.androidx.autofill)
    implementation(libs.kotlinx.coroutines.core)
}
