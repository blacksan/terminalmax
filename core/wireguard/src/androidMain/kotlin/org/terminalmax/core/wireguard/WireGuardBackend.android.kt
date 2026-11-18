// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import java.io.IOException

private object AndroidWgNative : WgNative {
    private inline fun <T> mapped(block: () -> T): T = try {
        block()
    } catch (e: IOException) {
        throw WireGuardException(e.message ?: "wgbridge failure", e)
    }

    // The bridge has no version call over JNI; the Go side reports it only through the C ABI.
    override fun version(): String = "terminalmax-wgbridge (android)"

    override fun start(config: ByteArray): Int = mapped { WgBridgeNative.nativeStart(config) }

    override fun openForward(handle: Int, target: String, tokenOut: ByteArray): Int =
        mapped { WgBridgeNative.nativeOpenForward(handle, target, tokenOut) }

    override fun stats(handle: Int): String = mapped { WgBridgeNative.nativeStats(handle) }

    override fun rebind(handle: Int) {
        val rc = WgBridgeNative.nativeRebind(handle)
        if (rc < 0) {
            throw WireGuardException(WgBridgeNative.nativeLastError().ifEmpty { "wgbridge: rebind failed ($rc)" })
        }
    }

    override fun stop(handle: Int) = WgBridgeNative.nativeStop(handle)
}

actual fun createWireGuardBackend(): WireGuardBackend {
    try {
        // Touching the object runs System.loadLibrary("wgbridge") once.
        WgBridgeNative.nativeLastError()
    } catch (e: UnsatisfiedLinkError) {
        throw WireGuardException("wgbridge: native library could not be loaded", e)
    } catch (e: ExceptionInInitializerError) {
        throw WireGuardException("wgbridge: native library could not be loaded", e)
    }
    return NativeWireGuardBackend(AndroidWgNative)
}
