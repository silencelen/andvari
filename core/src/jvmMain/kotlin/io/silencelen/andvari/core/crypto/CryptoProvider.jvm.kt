package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava

private val provider: CryptoProvider by lazy {
    // A host (the desktop app) may pre-extract the bundled libsodium and hand us its absolute path
    // via this property, to sidestep lazysodium's resource-loader: on a jpackage runtime whose
    // install path contains a space (Windows "Program Files") it mis-detects the app jar and calls
    // Paths.get on an unopened jar filesystem — FileSystemNotFoundException at the first crypto
    // call, before login, which read as a generic "Sign-in failed". SodiumJava(path) instead does a
    // plain JNA loadAbsolutePath and never touches that code. Unset (server, tests, dev) ⇒
    // lazysodium's own bundled loader, exactly as before — no behaviour change off the desktop.
    val path = System.getProperty("andvari.native.sodium.path")?.takeIf { it.isNotBlank() }
    val sodium = if (path != null) SodiumJava(path) else SodiumJava()
    LazySodiumCryptoProvider(LazySodiumJava(sodium))
}

actual fun createCryptoProvider(): CryptoProvider = provider
