package io.silencelen.andvari.app.trust

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The phone's model goes to the server as its name only when the server's `text` rule takes it. */
class DeviceNameTest {
    @Test
    fun aModelTheServerTakesIsTheName() {
        assertEquals("Pixel 9 Pro", checkedDeviceName("Pixel 9 Pro"))
        assertEquals(" SM-S928B ", checkedDeviceName(" SM-S928B "), "spaces are kept as they are")
        assertEquals("x".repeat(256), checkedDeviceName("x".repeat(256)))
    }

    @Test
    fun aModelTheServerWouldRefuseIsNotSent() {
        assertEquals("Android", checkedDeviceName(null))
        assertEquals("Android", checkedDeviceName(""))
        assertEquals("Android", checkedDeviceName("Pixel" + 0xAD.toChar() + "9"), "a soft hyphen")
        assertEquals("Android", checkedDeviceName("Pixel" + 0x200B.toChar() + "9"), "a zero-width space")
        assertEquals("Android", checkedDeviceName("Pixel\n9"), "a control character")
        assertEquals("Android", checkedDeviceName("x".repeat(257)), "longer than the server takes")
        assertEquals("Android", checkedDeviceName("Pixel " + 0xD83D.toChar()), "a lone surrogate")
    }

    @Test
    fun theEngineIsGivenTheCheckedName() {
        val seam = File("src/main/kotlin/io/silencelen/andvari/app/trust/TrustSeam.kt").readText()
        assertTrue("deviceName = checkedDeviceName(android.os.Build.MODEL)," in seam)
        assertTrue("deviceName = android.os.Build.MODEL" !in seam)
    }
}
