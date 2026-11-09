package io.silencelen.andvari.core.client

import io.silencelen.andvari.core.deleteDir
import io.silencelen.andvari.core.newTempDir
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class FileDeviceStateIosTest {
    private val root = newTempDir("andvari-device-state")
    private val dir = "$root/ns/user"

    @AfterTest fun cleanup() = deleteDir(root)

    @Test fun valuesSurviveANewInstanceInANewDirectory() {
        fileDeviceState(dir).set("personal.last", "v1")
        assertEquals("v1", fileDeviceState(dir).get("personal.last"))
        fileDeviceState(dir).set("personal.last", null)
        assertNull(fileDeviceState(dir).get("personal.last"))
    }
}
