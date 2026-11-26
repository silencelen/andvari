package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The dev build the owner installs was signed with the key checked into
 * the repository, so anyone with the repository could sign an update Android would accept over it. The debug signing
 * now takes a private key from local.properties or the environment when one is configured, and only otherwise falls
 * back to the checked-in key. Neither key, nor the dev build's id, ever goes into assetlinks.json.
 */
class DevSigningKeyTest {
    private val gradle = File("build.gradle.kts").readText()

    @Test
    fun theDebugSigningTakesAPrivateKeyWhenOneIsConfigured() {
        for (setting in listOf("andvari.devKeystore", "andvari.devKeystorePasswordFile", "andvari.devKeyAlias", "ANDVARI_DEV_KEYSTORE", "ANDVARI_DEV_KEYSTORE_PASSWORD_FILE", "ANDVARI_DEV_KEY_ALIAS")) {
            assertTrue(gradle.contains("\"$setting\""), "the build reads $setting")
        }
        assertTrue(gradle.contains("rootProject.file(\"local.properties\")"))
        assertTrue(gradle.contains("DevSigning(store, passwordFile.readText().trim(), alias)"), "the password is read from its file")
        val debug = gradle.substringAfter("getByName(\"debug\") {").substringBefore("if (keystoreProps.isNotEmpty())")
        assertTrue(debug.indexOf("val dev = devSigning") < debug.indexOf("file(\"debug.keystore\")"), "the private key first, the checked-in key only as the fall back")
        assertTrue(gradle.contains("require(store.isFile && passwordFile.isFile)"), "configured but missing fails, never a silent fall back")
    }

    @Test
    fun noDevIdAndNoDebugKeyInAssetLinks() {
        val links = listOf(File("../web/public/.well-known/assetlinks.json"), File("web/public/.well-known/assetlinks.json")).first { it.isFile }.readText()
        assertFalse(links.contains(".dev\""), "the dev build's id")
        assertFalse(links.uppercase().contains("1C:23:71:C3:9A:6A:D9:14"), "the checked-in debug key")
    }
}
