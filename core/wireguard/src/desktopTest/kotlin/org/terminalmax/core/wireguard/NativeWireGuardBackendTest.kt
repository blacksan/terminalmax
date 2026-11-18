// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Pure tests with a fake bridge: the native library cannot be loaded on the plain test job. */
class NativeWireGuardBackendTest {
    private class FakeNative : WgNative {
        var seenConfig: String? = null
        var stopCount = 0
        var failStart = false
        val calls = mutableListOf<String>()

        override fun version() = "fake"

        override fun start(config: ByteArray): Int {
            seenConfig = String(config)
            if (failStart) throw WireGuardException("bad config")
            return 7
        }

        override fun openForward(handle: Int, target: String, tokenOut: ByteArray): Int {
            calls += "forward:$handle:$target"
            tokenOut.fill(5)
            return 40_000
        }

        override fun stats(handle: Int) = """{"last_handshake_unix_ms":2000,"rx_bytes":3,"tx_bytes":4}"""

        override fun rebind(handle: Int) {
            calls += "rebind:$handle"
        }

        override fun stop(handle: Int) {
            stopCount++
        }
    }

    @Test
    fun startZeroFillsConfigOnSuccessAndFailure() {
        val fake = FakeNative()
        val backend = NativeWireGuardBackend(fake)
        val cfg = "[Interface]\n".toByteArray()
        backend.start(cfg).close()
        assertEquals("[Interface]\n", fake.seenConfig)
        assertTrue(cfg.all { it == 0.toByte() })

        fake.failStart = true
        val cfg2 = "[Interface]\n".toByteArray()
        assertFailsWith<WireGuardException> { backend.start(cfg2) }
        assertTrue(cfg2.all { it == 0.toByte() })
    }

    @Test
    fun startRejectsEmptyOversizedAndNulConfigs() {
        val backend = NativeWireGuardBackend(FakeNative())
        assertFailsWith<WireGuardException> { backend.start(ByteArray(0)) }
        assertFailsWith<WireGuardException> { backend.start(ByteArray(MAX_CONFIG_BYTES + 1) { 'a'.code.toByte() }) }
        val withNul = byteArrayOf('a'.code.toByte(), 0, 'b'.code.toByte())
        assertFailsWith<WireGuardException> { backend.start(withNul) }
        assertTrue(withNul.all { it == 0.toByte() })
    }

    @Test
    fun forwardStatsRebindAndIdempotentClose() {
        val fake = FakeNative()
        val tunnel = NativeWireGuardBackend(fake).start("x".toByteArray())
        val f = tunnel.openForward("10.99.0.1", 22)
        assertEquals(40_000, f.port)
        assertTrue(f.token.all { it == 5.toByte() })
        assertEquals("forward:7:10.99.0.1:22", fake.calls.single())
        val s = tunnel.stats()
        assertEquals(2L, s.lastHandshakeEpochSeconds)
        assertEquals(3L, s.rxBytes)
        tunnel.rebind()
        assertEquals("rebind:7", fake.calls.last())

        tunnel.close()
        tunnel.close()
        assertEquals(1, fake.stopCount)
        assertFailsWith<WireGuardException> { tunnel.stats() }
        assertFailsWith<WireGuardException> { tunnel.openForward("10.99.0.1", 22) }
        assertFailsWith<WireGuardException> { tunnel.rebind() }
    }

    @Test
    fun openForwardValidatesArgumentsBeforeCallingNative() {
        val fake = FakeNative()
        val tunnel = NativeWireGuardBackend(fake).start("x".toByteArray())
        assertFailsWith<IllegalArgumentException> { tunnel.openForward("not-an-ip", 22) }
        assertFailsWith<IllegalArgumentException> { tunnel.openForward("10.0.0.1", 0) }
        assertTrue(fake.calls.isEmpty())
        tunnel.close()
    }

    @Test
    fun closeWipesTheTokensOfEveryForward() {
        val tunnel = NativeWireGuardBackend(FakeNative()).start("x".toByteArray())
        val a = tunnel.openForward("10.99.0.1", 22)
        val b = tunnel.openForward("10.99.0.1", 22)
        assertTrue(a.token.all { it == 5.toByte() })
        tunnel.close()
        assertTrue(a.token.all { it == 0.toByte() })
        assertTrue(b.token.all { it == 0.toByte() })
    }

    @Test
    fun libraryFileNameByOs() {
        assertEquals("libwgbridge.dylib", nativeLibraryFileName("Mac OS X"))
        assertEquals("wgbridge.dll", nativeLibraryFileName("Windows 11"))
        assertEquals("libwgbridge.so", nativeLibraryFileName("Linux"))
    }
}
