package io.silencelen.andvari.core.app.engine

/**
 * What a screen read at each step of a sequence, in order: a test walks the engine and the fake through the same sequence
 * and compares their readings. `readings += x` adds [x] as one reading, a list included.
 */
internal class Readings : ArrayList<Any?>() {
    operator fun plusAssign(reading: Any?) {
        add(reading)
    }
}
