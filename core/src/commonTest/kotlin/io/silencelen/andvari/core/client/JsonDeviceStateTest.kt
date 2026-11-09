package io.silencelen.andvari.core.client

import kotlin.test.Test
import kotlin.test.assertEquals
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

    @Test fun aCorruptFileReadsAsEmpty() {
        assertNull(JsonDeviceState(MemoryFile("{not json")).get("a"))
    }
}
