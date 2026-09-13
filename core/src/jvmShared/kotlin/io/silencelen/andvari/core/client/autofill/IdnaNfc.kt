package io.silencelen.andvari.core.client.autofill

import java.text.Normalizer

/**
 * NFC for [Idna] on both JVM-family targets. `src/jvmShared` compiles into `jvmMain` AND
 * `androidMain`, so the desktop client and the phone canonicalize a saved host with the same
 * bytes by construction (the OriginCanon precedent, audit F37) — a one-sided edit could not
 * split the phone's and the laptop's idea of which item fills `xn--bcher-kva.de`.
 */
internal actual fun nfc(s: String): String = Normalizer.normalize(s, Normalizer.Form.NFC)
