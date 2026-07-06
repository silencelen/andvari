plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlinSerialization)
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.lazysodium.java)
    implementation(libs.jna)
}

application {
    mainClass.set("io.silencelen.andvari.tools.vectorgen.MainKt")
}

// `./gradlew :tools:vector-gen:run` rewrites spec/test-vectors/*.json in place.
tasks.named<JavaExec>("run") {
    args(rootProject.projectDir.resolve("spec/test-vectors").absolutePath)
}
