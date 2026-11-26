import java.security.KeyStore
import java.security.MessageDigest
import java.util.Properties

// Release signing: keystore.properties from ~/.andvari,
// env-overridable; absent → release builds UNSIGNED (CI-safe, and P2 ships debug first).
val keystorePropsFile = file(
    System.getenv("ANDVARI_KEYSTORE_PROPERTIES") ?: "${System.getProperty("user.home")}/.andvari/keystore.properties",
)
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

// The dev build's private signing key (see signingConfigs below). Null when not set up.
class DevSigning(val store: File, val password: String, val alias: String)

val devSigning: DevSigning? = run {
    val local = Properties().apply {
        val f = rootProject.file("local.properties")
        if (f.exists()) f.inputStream().use { load(it) }
    }
    fun setting(prop: String, env: String): String? = (System.getenv(env) ?: local.getProperty(prop))?.takeIf { it.isNotBlank() }
    val store = setting("andvari.devKeystore", "ANDVARI_DEV_KEYSTORE")?.let(::File)
    val passwordFile = setting("andvari.devKeystorePasswordFile", "ANDVARI_DEV_KEYSTORE_PASSWORD_FILE")?.let(::File)
    val alias = setting("andvari.devKeyAlias", "ANDVARI_DEV_KEY_ALIAS") ?: "andvaridev"
    if (store == null || passwordFile == null) {
        null
    } else {
        // Configured but missing is a failure, never a silent fall back to the public key.
        require(store.isFile && passwordFile.isFile) { "the dev signing key is configured but its keystore or password file is missing" }
        DevSigning(store, passwordFile.readText().trim(), alias)
    }
}

plugins {
    alias(libs.plugins.androidApplication)
    alias(libs.plugins.kotlinAndroid)
    alias(libs.plugins.kotlinCompose)
    alias(libs.plugins.kotlinSerialization)
    // Screen images in the JVM unit tests only (owner-approved 2026-11-16): the plugin adds its library to
    // testImplementation and the layout renderer to its own two configurations; the app's classpaths get nothing.
    alias(libs.plugins.paparazzi)
}

// The application id (onboarding and trust design §0.3, §15 `app-android`): ONE constant, here. `com.andvaripass.app`
// was confirmed on 2026-11-15; `-PandvariApplicationId=<id>` overrides it for a build. The R class `namespace` below
// stays `com.silencelen.andvari`, so no import or manifest class name changes with it.
val appOwnId = "com.andvaripass.app"
val andvariApplicationId: String = (findProperty("andvariApplicationId") as String?) ?: appOwnId

// One app, one key (decided on 2026-11-16): the app's own id is signed only with the key Google Play signs it with,
// wherever the build comes from. A release build of that id compares the configured release keystore's certificate
// with the fingerprint spec/public-instance.json records (`android.releaseCertSha256`) before anything is signed, and
// fails on any other (checkReleaseSigningKey below). Without release signing (no keystore.properties) nothing is
// checked and the output is unsigned, as before; an id given with -PandvariApplicationId is not checked.
// BEGIN releaseCertificateMismatch
/**
 * Null when the certificate under [keyAlias] in the keystore [storeFile] has the SHA-256 fingerprint [expectedSha256]
 * (colon-separated hex, either case); otherwise the one sentence a release build of [applicationId] fails with.
 */
fun releaseCertificateMismatch(storeFile: File, storePassword: String, keyAlias: String, expectedSha256: String, applicationId: String): String? {
    val store = KeyStore.getInstance(storeFile, storePassword.toCharArray())
    val cert = store.getCertificate(keyAlias)
    val actual = if (cert == null) "none" else MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString(":") { b -> "%02X".format(b) }
    val expected = expectedSha256.trim().uppercase()
    if (actual == expected) return null
    return "The release keystore's certificate (SHA-256 ${actual.take(23)}...) is not the app's own key (SHA-256 ${expected.take(23)}...): $applicationId is signed only with the app's own key."
}
// END releaseCertificateMismatch

// The store-build constants of the public instance (§0.3) come from spec/public-instance.json, the one in-repo source
// ("every app's build reads this file"). The module has no BuildConfig by decision, so a small Kotlin object is
// generated from it. A value that starts with "PLACEHOLDER:" does not exist yet: the app then bakes no public instance
// (and so offers no "Create an account on andvari"), and a release build refuses to be made (checkStoreConstants).
val publicInstanceSpec: File = rootProject.file("spec/public-instance.json")
val generatedConstantsDir: File = layout.buildDirectory.dir("generated/andvariConstants/kotlin").get().asFile

fun readPublicInstance(): Map<String, String> {
    @Suppress("UNCHECKED_CAST")
    val root = groovy.json.JsonSlurper().parse(publicInstanceSpec) as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val pi = root["PUBLIC_INSTANCE"] as Map<String, Any?>
    @Suppress("UNCHECKED_CAST")
    val android = root["android"] as Map<String, Any?>
    return mapOf(
        "origin" to pi["origin"].toString(),
        "instanceId" to pi["instanceId"].toString(),
        "card0Hash" to pi["card0Hash"].toString(),
        "kind" to pi["kind"].toString(),
        "name" to pi["name"].toString(),
        "joinBase" to root["joinBase"].toString(),
        "androidApplicationId" to android["applicationId"].toString(),
        "androidReleaseCertSha256" to android["releaseCertSha256"].toString(),
    )
}

val generateBuildConstants = tasks.register("generateAndvariBuildConstants") {
    inputs.file(publicInstanceSpec)
    outputs.dir(generatedConstantsDir)
    doLast {
        val v = readPublicInstance()
        fun lit(s: String) = "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$") + "\""
        val baked = listOf("origin", "instanceId", "card0Hash", "kind").none { v.getValue(it).startsWith("PLACEHOLDER:") }
        val dir = File(generatedConstantsDir, "io/silencelen/andvari/app/trust")
        dir.mkdirs()
        File(dir, "BuildConstants.kt").writeText(
            """
            |// Generated from spec/public-instance.json by :app-android:generateAndvariBuildConstants. Do not edit.
            |package io.silencelen.andvari.app.trust
            |
            |internal object BuildConstants {
            |    /** False while any public-instance value is a placeholder: the build then bakes no public instance. */
            |    const val BAKES_PUBLIC_INSTANCE: Boolean = $baked
            |    const val PUBLIC_ORIGIN: String = ${lit(v.getValue("origin"))}
            |    const val PUBLIC_INSTANCE_ID: String = ${lit(v.getValue("instanceId"))}
            |    const val PUBLIC_CARD0_HASH: String = ${lit(v.getValue("card0Hash"))}
            |    const val PUBLIC_KIND: String = ${lit(v.getValue("kind"))}
            |    const val PUBLIC_NAME: String = ${lit(v.getValue("name"))}
            |    const val JOIN_BASE: String = ${lit(v.getValue("joinBase"))}
            |}
            |""".trimMargin(),
        )
    }
}

// A release build refuses to be made while any store constant is a placeholder (spec/public-instance.json's own rule)
// or the application id is not the confirmed one. Wired in front of every release variant's preBuild, so no release
// task can run past it; run `:app-android:checkStoreConstants` alone to see what it says.
val checkStoreConstants = tasks.register("checkStoreConstants") {
    inputs.file(publicInstanceSpec)
    doLast {
        val v = readPublicInstance()
        val placeholders = v.filterValues { it.startsWith("PLACEHOLDER:") }.keys
        if (placeholders.isNotEmpty()) {
            throw GradleException("spec/public-instance.json still has placeholder values for $placeholders: a release build must not be made")
        }
        if (v.getValue("androidApplicationId") != andvariApplicationId) {
            throw GradleException("the application id $andvariApplicationId is not the one spec/public-instance.json records (${v["androidApplicationId"]})")
        }
    }
}
tasks.matching { it.name == "preReleaseBuild" }.configureEach { dependsOn(checkStoreConstants) }

// The release key's check (see releaseCertificateMismatch above), in front of every release variant's preBuild.
val checkReleaseSigningKey = tasks.register("checkReleaseSigningKey") {
    inputs.file(publicInstanceSpec)
    doLast {
        val mismatch = releaseCertificateMismatch(
            file(keystoreProps.getProperty("storeFile")),
            keystoreProps.getProperty("storePassword"),
            keystoreProps.getProperty("keyAlias"),
            readPublicInstance().getValue("androidReleaseCertSha256"),
            andvariApplicationId,
        )
        if (mismatch != null) throw GradleException(mismatch)
    }
}
if (keystoreProps.isNotEmpty() && andvariApplicationId == appOwnId) {
    tasks.matching { it.name == "preReleaseBuild" }.configureEach { dependsOn(checkReleaseSigningKey) }
}
tasks.matching { it.name == "preBuild" }.configureEach { dependsOn(generateBuildConstants) }

// Which of lazysodium-java's bundled libsodium builds fits the machine running the unit tests
// (see testOptions below).
val hostSodiumEntry: String = run {
    val os = System.getProperty("os.name").lowercase()
    val arch = System.getProperty("os.arch").lowercase()
    val arm = arch == "aarch64" || arch == "arm64"
    when {
        os.contains("mac") -> if (arm) "mac/aarch64/libsodium.dylib" else "mac/intel/libsodium.dylib"
        os.contains("windows") -> "windows64/libsodium.dll"
        else -> if (arm) "arm64/libsodium.so" else "linux64/libsodium.so"
    }
}
// The JVM the unit tests run on (see testOptions below).
val unitTestLauncher = extensions.getByType<JavaToolchainService>().launcherFor { languageVersion.set(JavaLanguageVersion.of(21)) }

val hostSodiumDir = layout.buildDirectory.dir("host-sodium")
val hostSodium: Configuration by configurations.creating { isTransitive = false }
val hostSodiumForUnitTests by tasks.registering(Sync::class) {
    from({ hostSodium.map { zipTree(it) } }) {
        include(hostSodiumEntry)
        eachFile { path = name }
        includeEmptyDirs = false
    }
    into(hostSodiumDir)
}

// The vector files the test build's phone check reads (src/debug/.../PhoneCryptoCheck.kt lists the same five).
val phoneCheckVectorsDir = layout.buildDirectory.dir("phone-check-vectors")
val phoneCheckVectors by tasks.registering(Sync::class) {
    from(rootProject.file("spec/test-vectors")) {
        include("kdf.json", "envelope.json", "seal.json", "sharedgrant.json", "usagekey.json")
    }
    into(phoneCheckVectorsDir)
}
// Every debug task that reads the debug assets (merging them, the unit tests' resources, lint) runs after the copy.
tasks.matching { t -> "Debug" in t.name && listOf("Assets", "UnitTest", "Lint").any { it in t.name } && t.name != "phoneCheckVectors" }
    .configureEach { dependsOn(phoneCheckVectors) }

android {
    namespace = "com.silencelen.andvari"
    // The app TARGETS Android 16 (API 36, below): Google Play takes nothing that targets less, on any track, since
    // 2026-08-31. It still COMPILES against 35. The screen drawings' renderer (Paparazzi 1.3.5 over layoutlib 14.0.11)
    // copies its own android.os.Build onto the one on the unit-test classpath, which is the compile platform's
    // android.jar, and API 36's has a nested class (VERSION_CODES_FULL) the renderer lacks, so not one screen is drawn
    // ("Array contains no element matching the predicate" in Renderer.configureBuildProperties). The app uses no API
    // that is new in 36. A pin (TargetSdkPinTest) reads both levels off the built debug manifest.
    compileSdk = 35

    sourceSets {
        getByName("main") { kotlin.srcDir(generatedConstantsDir) }
    }

    defaultConfig {
        applicationId = andvariApplicationId
        minSdk = 29
        targetSdk = 36
        versionCode = (System.getenv("ANDVARI_VERSIONCODE") ?: "1").toInt()
        versionName = "0.30.0"
        // The visible name (the launcher, the autofill picker). The debug build type below overrides it.
        manifestPlaceholders["appLabel"] = "andvari"
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
        // The test build's check of the phone's crypto (src/debug, PhoneCryptoCheck): the five vector files it reads,
        // copied from spec/test-vectors into the DEBUG build's assets only. A release build has none of them.
        getByName("debug") { assets.srcDir(phoneCheckVectorsDir) }
    }

    signingConfigs {
        // Checked-in debug key (devstore lesson: AGP's per-machine default debug key
        // breaks update continuity across build hosts).
        // The dev build the owner installs is signed with a PRIVATE key that is not in any
        // repository, when one is configured: `andvari.devKeystore`, `andvari.devKeystorePasswordFile` and
        // `andvari.devKeyAlias` in local.properties, or ANDVARI_DEV_KEYSTORE, ANDVARI_DEV_KEYSTORE_PASSWORD_FILE and
        // ANDVARI_DEV_KEY_ALIAS in the environment (the password is read from its file, never written here). Without
        // them the checked-in key below signs, as before. Neither key, nor the dev build's id, ever goes into
        // assetlinks.json.
        getByName("debug") {
            val dev = devSigning
            if (dev != null) {
                storeFile = dev.store
                storePassword = dev.password
                keyAlias = dev.alias
                keyPassword = dev.password
            } else {
                storeFile = file("debug.keystore")
                storePassword = "android"
                keyAlias = "androiddebugkey"
                keyPassword = "android"
            }
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
        // The test build for a real phone: it installs BESIDE every other andvari build and can never replace
        // or be mistaken for one. Its own application id (`<id>.dev`, so com.andvaripass.app.dev by default), its own
        // visible name, the checked-in debug key above, and no baked server (the public-instance values are still
        // placeholders). DevBuildIdentityTest pins all of it.
        debug {
            applicationIdSuffix = ".dev"
            manifestPlaceholders["appLabel"] = "andvari dev"
        }
        release {
            isMinifyEnabled = false
            signingConfig = if (keystoreProps.isNotEmpty()) signingConfigs.getByName("release") else null
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures { compose = true }

    // The JVM unit tests reach real crypto (the fake app API hands out a FakeVaultContent at every
    // unlock, and it seals with core's CryptoProvider). Core's Android actual binds libsodium
    // through lazysodium-android over JNA, and on the JVM neither JNA's dispatch library nor a
    // host libsodium comes from the .aar files. The test JVM gets both: JNA's own jar (it carries
    // libjnidispatch for every desktop platform) and the libsodium build that lazysodium-java
    // bundles, the same binary core's JVM tests grade, found through jna.library.path.
    testOptions {
        unitTests.all {
            // lazysodium-android 5.2.0 is compiled for Java 21 (class files of version 65), and these tests load it on
            // the computer: they alone run on a Java 21 launcher, found among the JDKs installed here (none is
            // downloaded). Everything else, the compile of this module included, stays on Java 17.
            it.javaLauncher.set(unitTestLauncher)
            it.dependsOn(hostSodiumForUnitTests)
            it.systemProperty("jna.library.path", hostSodiumDir.get().asFile.absolutePath)
            // TargetSdkPinTest reads the debug manifest exactly as it is built, so the debug tests build it first.
            if (it.name.contains("Debug")) {
                it.dependsOn("processDebugMainManifest")
                it.systemProperty(
                    "andvari.debugManifest",
                    layout.buildDirectory.file("intermediates/merged_manifest/debug/processDebugMainManifest/AndroidManifest.xml")
                        .get().asFile.absolutePath,
                )
            }
            // The screen images (Paparazzi, tests only) take minutes and look at nothing by themselves: they run only
            // when asked for with -PandvariScreens, and write their images under build/android-screens.
            if (project.hasProperty("andvariScreens")) {
                it.systemProperty("andvari.screens.dir", layout.buildDirectory.dir("android-screens").get().asFile.absolutePath)
                // -PandvariScreensOnly=a,b draws only the shots of those names (while working on a few screens).
                (project.findProperty("andvariScreensOnly") as String?)?.let { only -> it.systemProperty("andvari.screens.only", only) }
                it.maxHeapSize = "3g"
            } else {
                it.filter.excludeTestsMatching("*.ScreenImages*")
            }
        }
    }

    // The zero-key tripwire on the JVM unit tests: test machinery, in the test source set only.
    sourceSets {
        getByName("test") {
            kotlin.srcDir(rootProject.file("core/src/jvmTripwire/kotlin"))
            resources.srcDir(rootProject.file("core/src/jvmTripwire/resources"))
        }
    }
}
apply(from = rootProject.file("gradle/zero-key-tripwire.gradle.kts"))

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
    // QR codes for the recovery kit (and later links and device links), and the scanner's decoder. Pure Java,
    // no Google Play services (the design's direct channel).
    implementation(libs.zxing.core)
    // The in-app QR scanner's camera (owner-approved 2026-11-15): preview and analysis frames only; zxing-core decodes.
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    // Gate-2 §4.2 originKey byte-parity pins (OriginNamespaceTest) — pure-JVM, runs under
    // testDebugUnitTest. Explicit JUnit4 provider: this is the first AGP module with unit tests,
    // and AGP's testDebugUnitTest runs JUnit4 natively (no useJUnitPlatform wiring needed).
    testImplementation(kotlin("test-junit"))
    // See testOptions above: JNA's desktop dispatch library and a host libsodium for the JVM unit tests.
    testRuntimeOnly(libs.jna)
    // The shared code's own test server (FakeInstance and the helpers beside it), so the unit tests can walk the real
    // engine against it. Per build type: the server compiled in core's own Android unit tests of the same build type,
    // against the same variant of core these tests run on. Unit-test class paths only, never the app or its package.
    "testDebugImplementation"(project(path = ":core", configuration = "testServerAndroidDebugElements"))
    "testReleaseImplementation"(project(path = ":core", configuration = "testServerAndroidReleaseElements"))
    hostSodium(libs.lazysodium.java)
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

kotlin {
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
}
