package io.silencelen.andvari.app

import java.io.File
import java.security.KeyStore
import java.security.MessageDigest

// The release build's key check, as app-android/build.gradle.kts has it: the text between the two marks below is the
// same, character for character, in both files (ReleaseSigningCheckTest compares them), so this copy is the one tested.

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
