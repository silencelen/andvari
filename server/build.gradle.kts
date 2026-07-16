plugins {
    alias(libs.plugins.kotlinJvm)
    alias(libs.plugins.kotlinSerialization)
    alias(libs.plugins.shadow)
    application
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(project(":core"))
    implementation(libs.lazysodium.java) // pwhash_str verifier — server-only primitive
    implementation(libs.jna)

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.websockets)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.server.auth)
    implementation(libs.ktor.server.rate.limit)
    implementation(libs.ktor.server.status.pages)
    implementation(libs.ktor.server.metrics.micrometer)
    implementation(libs.ktor.serialization.kotlinx.json)
    implementation(libs.ktor.client.core)
    implementation(libs.ktor.client.java)

    implementation(libs.sqlite.jdbc)
    implementation(libs.logback.classic)
    implementation(libs.angus.mail) // cut 4 email-invite: SMTP submission (jakarta.mail impl)
    implementation(libs.micrometer.prometheus)

    testImplementation(libs.kotlin.test)
    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.ktor.client.content.negotiation)
    testImplementation(libs.ktor.client.websockets)
}

application {
    mainClass.set("io.silencelen.andvari.server.MainKt")
}

// /selfhost bundle (design 2026-07-15 §8.1): bake the self-host guide + deploy artifacts into the
// jar as classpath resources under selfhost/ (read by SelfHost.kt) so EVERY instance serves its own
// self-host path. The source files are owned by the docs/deploy lane (docs/self-hosting.md +
// deploy/{docker-compose.yml,andvari.env.template,bringup.sh}); files absent at build time simply
// don't bundle — the route then serves a stub page / 404s the artifact, never the SPA fallback.
tasks.processResources {
    from(rootProject.file("docs/self-hosting.md")) { into("selfhost") }
    from(rootProject.file("deploy")) {
        include("docker-compose.yml", "docker-compose.caddy.yml", "andvari.env.template", "bringup.sh")
        into("selfhost")
    }
}

tasks.shadowJar {
    archiveBaseName.set("andvari-server")
    archiveClassifier.set("")
    mergeServiceFiles()
}
