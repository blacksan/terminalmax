// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull

class StatsParserTest {
    @Test
    fun parsesMinimalJsonWithoutHandshake() {
        val s = parseTunnelStats("""{"last_handshake_unix_ms":0,"rx_bytes":0,"tx_bytes":0}""")
        assertNull(s.lastHandshakeEpochSeconds)
        assertEquals(0L, s.rxBytes)
        assertEquals(0L, s.txBytes)
        assertNull(s.lastForwardError)
        assertNull(s.lastDeviceError)
    }

    @Test
    fun parsesHandshakeAndCountersAndErrors() {
        val s = parseTunnelStats(
            """{"last_handshake_unix_ms":1700000123456,"rx_bytes":4096,"tx_bytes":2048,""" +
                """"last_forward_error":"forward: client failed authentication","last_device_error":"boom"}""",
        )
        assertEquals(1_700_000_123L, s.lastHandshakeEpochSeconds)
        assertEquals(4096L, s.rxBytes)
        assertEquals(2048L, s.txBytes)
        assertEquals("forward: client failed authentication", s.lastForwardError)
        assertEquals("boom", s.lastDeviceError)
    }

    @Test
    fun ignoresUnknownKeys() {
        val s = parseTunnelStats("""{"rx_bytes":1,"tx_bytes":2,"future_field":{"a":1}}""")
        assertEquals(1L, s.rxBytes)
        assertEquals(2L, s.txBytes)
    }

    @Test
    fun garbageIsAWireGuardException() {
        assertFailsWith<WireGuardException> { parseTunnelStats("not json") }
        assertFailsWith<WireGuardException> { parseTunnelStats("") }
    }

    @Test
    fun forwardTargetFormatting() {
        assertEquals("10.99.0.1:22", formatForwardTarget("10.99.0.1", 22))
        assertEquals("[fd00::1]:2222", formatForwardTarget("fd00::1", 2222))
    }

    @Test
    fun forwardTargetValidation() {
        assertFailsWith<IllegalArgumentException> { formatForwardTarget("", 22) }
        assertFailsWith<IllegalArgumentException> { formatForwardTarget("router.example", 22) }
        assertFailsWith<IllegalArgumentException> { formatForwardTarget("[fd00::1]", 22) }
        assertFailsWith<IllegalArgumentException> { formatForwardTarget("10.0.0.1:22", 22) }
        assertFailsWith<IllegalArgumentException> { formatForwardTarget("10.0.0.1", 0) }
        assertFailsWith<IllegalArgumentException> { formatForwardTarget("10.0.0.1", 65536) }
    }

    @Test
    fun loopbackForwardCopiesAndRedactsToken() {
        val src = ByteArray(32) { it.toByte() }
        val f = LoopbackForward(4242, src)
        src.fill(0)
        assertEquals(31, f.token[31].toInt())
        f.token.fill(9) // a copy: does not affect the stored token
        assertEquals(5, f.token[5].toInt())
        assertFalse(f.toString().contains("31"))
        assertEquals("LoopbackForward(port=4242, token=***)", f.toString())
        f.wipe()
        assertEquals(0, f.token[5].toInt())
    }

    @Test
    fun loopbackForwardValidatesArguments() {
        assertFailsWith<IllegalArgumentException> { LoopbackForward(0, ByteArray(32)) }
        assertFailsWith<IllegalArgumentException> { LoopbackForward(70000, ByteArray(32)) }
        assertFailsWith<IllegalArgumentException> { LoopbackForward(1000, ByteArray(31)) }
    }
}
