// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * The calls of the native bridge, one implementation per platform (JNI on Android, JNA on the
 * desktop). Implementations translate every native failure into [WireGuardException] and must
 * not retain any argument.
 */
internal interface WgNative {
    fun version(): String

    /** @return a handle > 0. [config] is not modified; the caller zero-fills it. */
    fun start(config: ByteArray): Int

    /** @param tokenOut exactly 32 bytes. @return the loopback port. */
    fun openForward(handle: Int, target: String, tokenOut: ByteArray): Int

    fun stats(handle: Int): String

    fun rebind(handle: Int)

    fun stop(handle: Int)
}

internal class NativeWireGuardBackend(private val native: WgNative) : WireGuardBackend {
    override fun version(): String = native.version()

    override fun start(configText: ByteArray): WireGuardTunnel {
        try {
            if (configText.isEmpty()) throw WireGuardException("wgbridge: config is empty")
            if (configText.size > MAX_CONFIG_BYTES) throw WireGuardException("wgbridge: config too large")
            if (configText.any { it == 0.toByte() }) throw WireGuardException("wgbridge: config contains a NUL byte")
            val handle = native.start(configText)
            if (handle <= 0) throw WireGuardException("wgbridge: start failed ($handle)")
            return NativeWireGuardTunnel(native, handle)
        } finally {
            configText.fill(0)
        }
    }
}

/**
 * Calls take the read lock and close takes the write lock, so a handle is never used after
 * `wgbStop` while calls from several threads can still overlap.
 */
internal class NativeWireGuardTunnel(
    private val native: WgNative,
    private val handle: Int,
) : WireGuardTunnel {
    private val lock = ReentrantReadWriteLock()
    private var closed = false

    /** Forwards handed out by this tunnel; their tokens are wiped when the tunnel closes. */
    private val forwards = ArrayDeque<LoopbackForward>()

    private inline fun <T> live(block: () -> T): T = lock.read {
        if (closed) throw WireGuardException("wgbridge: tunnel is closed")
        block()
    }

    /** Called while holding the read lock, so it can never race with [close]. */
    private fun track(forward: LoopbackForward): LoopbackForward {
        synchronized(forwards) {
            // A forward expires after 5 s without a client, so the oldest tokens are long useless.
            while (forwards.size >= MAX_TRACKED_FORWARDS) forwards.removeFirst().wipe()
            forwards.addLast(forward)
        }
        return forward
    }

    override fun openForward(targetIp: String, port: Int): LoopbackForward {
        val target = formatForwardTarget(targetIp, port)
        val token = ByteArray(LoopbackForward.TOKEN_SIZE)
        try {
            return live {
                val localPort = native.openForward(handle, target, token)
                if (localPort !in 1..65535) throw WireGuardException("wgbridge: invalid forward port ($localPort)")
                track(LoopbackForward(localPort, token))
            }
        } finally {
            token.fill(0)
        }
    }

    override fun stats(): TunnelStats = parseTunnelStats(live { native.stats(handle) })

    override fun rebind() {
        live { native.rebind(handle) }
    }

    override fun close() {
        lock.write {
            if (closed) return
            closed = true
            try {
                native.stop(handle)
            } finally {
                synchronized(forwards) {
                    forwards.forEach { it.wipe() }
                    forwards.clear()
                }
            }
        }
    }

    private companion object {
        const val MAX_TRACKED_FORWARDS = 64
    }
}
