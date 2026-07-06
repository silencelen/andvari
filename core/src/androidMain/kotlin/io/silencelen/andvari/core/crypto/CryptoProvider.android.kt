package io.silencelen.andvari.core.crypto

import com.goterl.lazysodium.LazySodiumAndroid
import com.goterl.lazysodium.SodiumAndroid

private val provider: CryptoProvider by lazy {
    LazySodiumCryptoProvider(LazySodiumAndroid(SodiumAndroid()))
}

actual fun createCryptoProvider(): CryptoProvider = provider
