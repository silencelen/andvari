package io.silencelen.andvari.core.crypto

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Security review 2026-10, root cause A (A4 review carry-forward, closed in A5): the anchored escrow
 * verifier is callable only from the escrow open path. In Kotlin that is `internal` (no app or tool module
 * compiles a call to it) and its one product caller is [Escrow.open]; this pins both against a refactor.
 */
class EscrowVerifierVisibilityTest {
    private val repo = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set")).resolve("../..").canonicalFile

    @Test
    fun verifyEscrowIsInternalAndOnlyEscrowOpenCallsIt() {
        val ss = repo.resolve("core/src/commonMain/kotlin/io/silencelen/andvari/core/crypto/SignedStatement.kt").readText()
        assertTrue(Regex("""internal fun verifyEscrow\(""").containsMatchIn(ss), "SignedStatement.verifyEscrow must be internal")
        val callers = repo.resolve("core/src/commonMain").walk()
            .filter { it.isFile && it.extension == "kt" && it.readText().contains("SignedStatement.verifyEscrow(") }
            .map { it.name }.toList()
        assertEquals(listOf("Escrow.kt"), callers, "only the escrow open path verifies an escrow statement")
        for (module in listOf("app-android/src", "app-desktop/src", "tools", "server/src")) {
            val leaks = repo.resolve(module).walk().filter { it.isFile && it.extension == "kt" && it.readText().contains("verifyEscrow(") }.map { it.path }.toList()
            assertEquals(emptyList(), leaks, "$module must not reference verifyEscrow")
        }
    }
}
