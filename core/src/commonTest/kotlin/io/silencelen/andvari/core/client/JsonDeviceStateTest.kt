package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class JsonDeviceStateTest {
    private class MemoryFile(var text: String? = null) : DeviceStateFile {
        var writes = 0
        override fun read(): String? = text
        override fun replace(text: String) { this.text = text; writes++ }
    }

    @Test fun valuesSurviveANewInstance() {
        val file = MemoryFile()
        JsonDeviceState(file).set("a", "1")
        assertEquals("1", JsonDeviceState(file).get("a"))
    }

    @Test fun nullRemoves() {
        val file = MemoryFile()
        val state = JsonDeviceState(file)
        state.set("a", "1")
        state.set("a", null)
        assertNull(state.get("a"))
    }

    @Test fun anUnchangedValueDoesNotWrite() {
        val file = MemoryFile()
        val state = JsonDeviceState(file)
        state.set("a", "1")
        state.set("a", "1")
        state.set("missing", null)
        assertEquals(1, file.writes)
    }

    /** Design §4.4 "A trust record that cannot be read is not an empty one": a file that does not parse is unknown, never
     *  empty (it held pins and marks), and the whole-map write is never made over it. */
    @Test fun aCorruptFileIsNeverReadAsEmptyNorWrittenOver() {
        val file = MemoryFile("{not json")
        val state = JsonDeviceState(file)
        assertFailsWith<IllegalStateException> { state.get("a") }
        assertFailsWith<IllegalStateException> { state.set("a", "1") }
        assertEquals("{not json", file.text)
    }

    /** A file that is there and cannot be read now (iOS, the device locked) is never taken for an empty one: a write after
     *  it would replace every record. */
    @Test fun anUnreadableFileIsNeverWrittenOver() {
        val file = object : DeviceStateFile {
            var writes = 0
            override fun read(): String? = error("protected")
            override fun replace(text: String) { writes++ }
        }
        val state = JsonDeviceState(file)
        assertFailsWith<IllegalStateException> { state.get("a") }
        assertFailsWith<IllegalStateException> { state.set("a", "1") }
        assertEquals(0, file.writes)
    }
}
