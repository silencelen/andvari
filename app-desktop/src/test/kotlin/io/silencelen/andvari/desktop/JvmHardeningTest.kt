package io.silencelen.andvari.desktop

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The JVM the app runs in. */
class JvmHardeningTest {
    private val buildScript: String by lazy {
        listOf(File("build.gradle.kts"), File("app-desktop/build.gradle.kts")).first { it.isFile }.readText()
    }

    @Test
    fun theBuildGivesThePackagedAppAndTheRunTaskTheHardening() {
        assertTrue(Regex("""hardenedJvmArgs = listOf\("-XX:\+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash"\)""").containsMatchIn(buildScript))
        assertTrue("jvmArgs += hardenedJvmArgs" in buildScript, "inside compose.desktop.application: packaged and run alike")
        assertTrue("-XX:ErrorFile=" in buildScript && ".andvari-desktop" in buildScript, "the run task's error file is inside the app's directory")
    }

    @Test
    fun whatIsMissingIsNamed() {
        assertEquals(listOf("-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash"), missingJvmHardening(emptyList()))
        assertEquals(emptyList(), missingJvmHardening(listOf("-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash")))
        assertEquals(
            listOf("-XX:+DisableAttachMechanism"),
            missingJvmHardening(listOf("-XX:+DisableAttachMechanism", "-XX:-CreateCoredumpOnCrash", "-XX:-DisableAttachMechanism")),
            "a later option of the same name wins",
        )
    }
}
