package io.silencelen.andvari.core.client

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * INV-SEAL routing tripwire (security review 2026-10, root cause A §5.1; branch A1b): product code seals item plaintext
 * ONLY through [Account.sealItem] with an explicit [SealProvenance] (via SyncEngine's `sealFor`, which adds the INV-HOME
 * cross-check). [Account.encryptItem] is the provenance-free test shim; a product file that calls it fails here, on
 * every native surface (core, Android, desktop, the tools CLIs).
 */
class ItemSealRoutingTest {
    private val repo = File(System.getProperty("andvari.vectors.dir") ?: error("andvari.vectors.dir not set")).absoluteFile.parentFile.parentFile

    private fun productSources(): List<File> = listOf(
        "core/src/commonMain", "core/src/jvmShared", "core/src/jvmMain", "core/src/androidMain",
        "app-android/src/main", "app-desktop/src/main", "tools",
    ).map { File(repo, it) }.filter { it.exists() }.flatMap { root ->
        root.walkTopDown().filter { it.isFile && it.extension == "kt" && "/src/test/" !in it.path && "/build/" !in it.path }.toList()
    }

    @Test
    fun productCodeNeverCallsTheProvenanceFreeShim() {
        val files = productSources()
        assertTrue(files.size > 50, "the scan found the product sources (${files.size} files under $repo)")
        val offenders = files.flatMap { f ->
            f.readLines().mapIndexedNotNull { i, line ->
                val code = line.substringBefore("//")
                if (Regex("""\.encryptItem\(""").containsMatchIn(code)) "${f.relativeTo(repo)}:${i + 1}: ${line.trim()}" else null
            }
        }
        assertEquals(emptyList(), offenders, "seal item plaintext through Account.sealItem(provenance, …) / SyncEngine.sealFor")
    }

    @Test
    fun theOnlySealSiteIsSealUnderBehindSealItem() {
        val account = File(repo, "core/src/commonMain/kotlin/io/silencelen/andvari/core/client/Account.kt").readText()
        assertEquals(1, Regex("""Ad\.item\(vaultId, itemId, fv\)""").findAll(account).count(), "one item seal in Account")
        assertTrue(account.contains("if (!canSealUnder(vaultId)) throw VaultKeyNotVerifiedException(vaultId)"), "sealItem gates INV-WRITE-KEY")
    }
}
