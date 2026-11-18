package org.terminalmax.core.model

import kotlin.test.Test
import kotlin.test.assertEquals

class HostIdTest {
    @Test
    fun wrapsValue() {
        assertEquals("host-1", HostId("host-1").value)
    }
}
