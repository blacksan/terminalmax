// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import java.io.IOException

/**
 * JNI declarations of libwgbridge.so. The names and signatures must match
 * native/wgbridge/cmd/libwgbridge/jni_android.c exactly
 * (`Java_org_terminalmax_core_wireguard_WgBridgeNative_*`).
 */
internal object WgBridgeNative {
    init {
        System.loadLibrary("wgbridge")
    }

    /** @return a handle > 0. The caller must zero-fill [config] afterwards. */
    @Throws(IOException::class)
    external fun nativeStart(config: ByteArray): Int

    /** Process-global message of the last failure. */
    external fun nativeLastError(): String

    /** @param tokenOut exactly 32 bytes. @return the loopback port. */
    @Throws(IOException::class)
    external fun nativeOpenForward(handle: Int, target: String, tokenOut: ByteArray): Int

    @Throws(IOException::class)
    external fun nativeStats(handle: Int): String

    /** @return 0, or a negative code (message via [nativeLastError]). */
    external fun nativeRebind(handle: Int): Int

    external fun nativeStop(handle: Int)
}
