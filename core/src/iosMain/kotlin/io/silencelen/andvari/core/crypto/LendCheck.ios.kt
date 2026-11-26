package io.silencelen.andvari.core.crypto

/** No test seam on Kotlin/Native: a lend's answer is never inspected here, in the app or in its tests (spec 01 §8 rule 1). */
internal actual fun lendCheckSwitch(): (() -> Boolean)? = null
