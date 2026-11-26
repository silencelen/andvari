package io.silencelen.andvari.cli

import io.silencelen.andvari.cli.e2e.TestServer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The preview says of each shared vault whether the person owned it or was a member: restoring one someone else still
 * has makes a second copy. Before, the tool said neither.
 */
class RestoreSharedRoleTest {
    @Test fun thePreviewSaysOfEachSharedVaultWhetherThePersonOwnedItOrWasAMember() {
        TestServer().use { s ->
            val w = CliWorld(s)
            val me = w.account("me@example.org")
            val backup = RestoreFiles.write(w.tmp, "old.andvari", RestoreFiles.bytes(RestoreFiles.threeVaults()))

            val text = w.run(me, "restore", "--backup", backup.path, "--dry-run", env = { RestoreFiles.env[it] }).ok().lines()
            assertTrue(text.single { it.contains("“Family”") }.contains("you owned it"), text.joinToString("\n"))
            assertTrue(text.single { it.contains("“Work”") }.contains("you were a member"), text.joinToString("\n"))

            val doc = Json.parseToJsonElement(w.run(me, "restore", "--backup", backup.path, "--dry-run", "--json", env = { RestoreFiles.env[it] }).ok()).jsonObject
            val owned = doc.getValue("vaults").jsonArray.associate { it.jsonObject.getValue("name").jsonPrimitive.content to it.jsonObject.getValue("owned").jsonPrimitive.boolean }
            assertEquals(mapOf("Personal" to true, "Family" to true, "Work" to false), owned)
        }
    }
}
