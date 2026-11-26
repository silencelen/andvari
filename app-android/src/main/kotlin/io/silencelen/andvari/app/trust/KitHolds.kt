package io.silencelen.andvari.app.trust

import androidx.compose.runtime.mutableIntStateOf
import io.silencelen.andvari.core.app.KitDocument
import io.silencelen.andvari.core.app.KitScreen

/**
 * What the app itself still holds of a recovery kit outside the screens: the print adapter's document and page, kept
 * until the system's print screen is done with them. A lock takes the kit off the screen and out of memory, so it takes
 * these too: [TrustModel] calls [dropAll] as soon as no kit is on show. What the system's print screen already has is
 * the person's own act. No Android type here, so the JVM tests drive it.
 */
internal object KitHolds {
    /** One thing that holds kit material; [drop] lets go of it for good. */
    fun interface Held {
        fun drop()
    }

    private val held = LinkedHashSet<Held>()

    @Synchronized
    fun hold(h: Held) {
        held += h
    }

    @Synchronized
    fun release(h: Held) {
        held -= h
    }

    /** How many are held now (for tests). */
    val count: Int @Synchronized get() = held.size

    /**
     * Every holder lets go of its kit material; none is held afterwards. One that fails does not stop the others, and
     * its failure is thrown afterwards (the model contains it and says so), never swallowed.
     */
    fun dropAll() {
        val all = synchronized(this) { held.toList().also { held.clear() } }
        var failed: Throwable? = null
        for (h in all) {
            try {
                h.drop()
            } catch (t: Throwable) {
                if (failed == null) failed = t else failed.addSuppressed(t)
            }
        }
        failed?.let { throw it }
    }
}

/**
 * What the kit screens draw from, owned by the model ([TrustModel.kitScreen]): the kit's document, its QR picture, and
 * the groups typed back. The composition keeps only this holder, never the kit itself, so a lock empties it whether or
 * not anything recomposes (the app away, the activity stopped): [KitHolds.dropAll] reaches it, and so does the model's
 * own lock and cover. Each value is kept for the [KitScreen] it was made for, as `remember(kit)` kept it before.
 */
internal class KitScreenHold : KitHolds.Held {
    private var docFor: KitScreen? = null

    /** The document of the kit on show, made by [make] once per kit; null once dropped. */
    var document: KitDocument? = null
        private set

    private var pictureOf: KitDocument? = null

    /** The QR picture of [document] (a Bitmap in the app; no Android type here, so the JVM tests drive it). */
    var picture: Any? = null
        private set

    private var typedFor: KitScreen? = null
    private var typedNow: MutableList<String> = mutableListOf()

    /** Counts the changes to [typedNow], so that the screen recomposes; the groups themselves never enter Compose state. */
    private val typedChanges = mutableIntStateOf(0)

    fun documentFor(kit: KitScreen, make: () -> KitDocument?): KitDocument? {
        if (docFor !== kit) {
            docFor = kit
            document = make()
            pictureOf = null
            picture = null
            KitHolds.hold(this)
        }
        return document
    }

    fun pictureFor(doc: KitDocument, make: (KitDocument) -> Any): Any {
        if (pictureOf !== doc || picture == null) {
            pictureOf = doc
            picture = make(doc)
        }
        return picture!!
    }

    /** The groups typed back on [kit]'s confirm step, [n] fields; empty fields for a new kit. Read in composition. */
    fun typed(kit: KitScreen, n: Int): List<String> {
        typedChanges.intValue
        if (typedFor !== kit) {
            typedFor = kit
            typedNow = MutableList(n) { "" }
            KitHolds.hold(this)
        }
        return typedNow.toList()
    }

    /** Field [i] of [kit]'s confirm step now reads [v]; nothing for a kit no longer held (a lock overtook the keystroke). */
    fun type(kit: KitScreen, i: Int, v: String) {
        if (typedFor !== kit || i !in typedNow.indices) return
        typedNow[i] = v
        typedChanges.intValue++
    }

    override fun drop() {
        docFor = null
        document = null
        pictureOf = null
        picture = null
        typedFor = null
        typedNow = mutableListOf()
        typedChanges.intValue++
    }
}
