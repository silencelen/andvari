package io.silencelen.andvari.core.client

/**
 * Shared passphrase-strength estimator — an EXACT Kotlin mirror of web/src/ui/strength.ts
 * `estimateStrength` (same class weights, same 40/60/80/110-bit thresholds, scores 0..4)
 * so both impls enforce the same spec 07 §2.3 backup-passphrase floor (score ≥ 3).
 *
 * Rough entropy proxy — length + character-class diversity (not a substitute for a real
 * estimator). Length counts UTF-16 units, matching JS `String.length`.
 */
object Strength {
    /** spec 07 §2.3: backup passphrases must score at least this. */
    const val BACKUP_FLOOR = 3

    /** Score → label, index-aligned with web's STRENGTH_LABELS. */
    val LABELS: List<String> = listOf("very weak", "weak", "fair", "good", "strong")

    fun estimateStrength(pw: String): Int {
        var classes = 0
        if (pw.any { it in 'a'..'z' }) classes++
        if (pw.any { it in 'A'..'Z' }) classes++
        if (pw.any { it in '0'..'9' }) classes++
        if (pw.any { it !in 'a'..'z' && it !in 'A'..'Z' && it !in '0'..'9' }) classes++
        val bits = pw.length * when {
            classes <= 1 -> 2.0
            classes == 2 -> 3.5
            classes == 3 -> 5.0
            else -> 6.0
        }
        return when {
            bits < 40 -> 0
            bits < 60 -> 1
            bits < 80 -> 2
            bits < 110 -> 3
            else -> 4
        }
    }

    fun label(score: Int): String = LABELS[score.coerceIn(0, LABELS.size - 1)]
}
