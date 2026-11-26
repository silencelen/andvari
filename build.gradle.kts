plugins {
    alias(libs.plugins.kotlinMultiplatform) apply false
    alias(libs.plugins.kotlinJvm) apply false
    alias(libs.plugins.kotlinSerialization) apply false
    alias(libs.plugins.androidLibrary) apply false
    alias(libs.plugins.androidApplication) apply false
    alias(libs.plugins.kotlinAndroid) apply false
    alias(libs.plugins.kotlinCompose) apply false
    alias(libs.plugins.composeMultiplatform) apply false
    // Declared here beside the Android and Kotlin plugins, so it resolves against the build's own AGP and Kotlin
    // plugin versions instead of fetching the older ones it was built against. Applied in app-android only.
    alias(libs.plugins.paparazzi) apply false
}

// Every test task gets its own temporary directory: emptied when the task starts, removed when it passes. A test
// that leaves files behind then cannot fill the machine's shared temporary directory (one day of test runs once
// left twelve thousand directories there). It stays under the system's temporary directory, on a short path,
// because a test may put a socket in it and a socket's path has a length limit. After a failed run the files stay
// until the next run, for whoever is looking into the failure.
subprojects {
    tasks.withType<Test>().configureEach {
        val tree = Integer.toHexString(rootProject.projectDir.absolutePath.hashCode())
        val dir = File(System.getProperty("java.io.tmpdir"), "andvari-tests/$tree/${project.name}.$name")
        doFirst {
            dir.deleteRecursively()
            dir.mkdirs()
        }
        doLast { dir.deleteRecursively() }
        systemProperty("java.io.tmpdir", dir.absolutePath)
    }
}
