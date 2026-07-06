package io.silencelen.andvari.core.crypto

data class GeneratorOptions(
    val length: Int = 20,
    val lower: Boolean = true,
    val upper: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    val avoidAmbiguous: Boolean = true,
)

/** Unbiased generation via rejection sampling; guarantees ≥1 char per enabled class. */
object PasswordGenerator {
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*-_=+?"
    private const val AMBIGUOUS = "lIO01"

    fun generate(crypto: CryptoProvider, options: GeneratorOptions = GeneratorOptions()): String {
        require(options.length in 8..128) { "length out of range" }
        val classes = buildList {
            if (options.lower) add(LOWER)
            if (options.upper) add(UPPER)
            if (options.digits) add(DIGITS)
            if (options.symbols) add(SYMBOLS)
        }.map { cls ->
            if (options.avoidAmbiguous) cls.filter { it !in AMBIGUOUS } else cls
        }
        require(classes.isNotEmpty()) { "at least one character class required" }
        require(options.length >= classes.size) { "length shorter than enabled classes" }
        val all = classes.joinToString("")

        // One guaranteed char per class, remainder from the union, then shuffle.
        val chars = ArrayList<Char>(options.length)
        for (cls in classes) chars.add(cls[uniform(crypto, cls.length)])
        repeat(options.length - classes.size) { chars.add(all[uniform(crypto, all.length)]) }
        for (i in chars.indices.reversed()) {
            if (i == 0) break
            val j = uniform(crypto, i + 1)
            val tmp = chars[i]; chars[i] = chars[j]; chars[j] = tmp
        }
        return chars.joinToString("")
    }

    /** Uniform int in [0, bound) by rejection sampling over single bytes. */
    private fun uniform(crypto: CryptoProvider, bound: Int): Int {
        require(bound in 1..256)
        val limit = 256 - (256 % bound)
        while (true) {
            val b = crypto.randomBytes(1)[0].toInt() and 0xFF
            if (b < limit) return b % bound
        }
    }
}
