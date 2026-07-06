package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava

private val provider: CryptoProvider by lazy {
    LazySodiumCryptoProvider(LazySodiumJava(SodiumJava()))
}

actual fun createCryptoProvider(): CryptoProvider = provider
