package io.silencelen.andvari.app.trust

/**
 * What a walk's step draws, printed into the test report's output (`WALK|<step>|<line>`), with a line without wording
 * flagged. The walks' assertions are of what the screen must say; this only lets a reader follow them step by step.
 */
internal object WalkPrint {
    private val bare = setOf(Placeholder.TROUBLE, Placeholder.REFUSAL)

    /** A line the phone draws with no words for its result: the trouble or the refusal without wording. */
    fun isBare(t: UiText?): Boolean = (t as? UiText.Ph)?.placeholder in bare

    fun draws(step: String, lines: List<UiText?>) {
        val shown = lines.filterNotNull()
        if (shown.isEmpty()) println("WALK|$step|(nothing)")
        for (l in shown) println("WALK|$step|${if (isBare(l)) "WITHOUT WORDING: " else ""}${l.shown()}")
    }

    fun note(step: String, what: Any?) = println("WALK|$step|$what")
}
