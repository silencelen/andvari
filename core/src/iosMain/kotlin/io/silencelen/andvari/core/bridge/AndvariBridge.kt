package io.silencelen.andvari.core.bridge

import io.silencelen.andvari.core.client.ANDVARI_CLIENT_VERSION
import io.silencelen.andvari.core.crypto.GeneratorOptions
import io.silencelen.andvari.core.crypto.PasswordGenerator
import io.silencelen.andvari.core.crypto.createCryptoProvider

/** The surface Swift calls. Keys stay on the Kotlin side; Swift only receives what it displays. */
object AndvariBridge {
    fun coreVersion(): String = ANDVARI_CLIENT_VERSION

    fun generatePassword(length: Int): String =
        PasswordGenerator.generate(createCryptoProvider(), GeneratorOptions(length = length))
}
