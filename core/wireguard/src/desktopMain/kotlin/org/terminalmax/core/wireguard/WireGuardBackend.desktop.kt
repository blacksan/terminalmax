// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import java.io.File

/**
 * The C ABI exactly as exported by native/wgbridge/cmd/libwgbridge/main.go. `char *` and
 * `unsigned char *` parameters are byte arrays (JNA copies them in and back out); the config
 * is passed as a native [Pointer] so that it can be zeroed.
 */
internal interface WgBridgeLib : Library {
    fun wgbStart(confText: Pointer, errBuf: ByteArray, errLen: Int): Int
    fun wgbOpenForward(handle: Int, target: ByteArray, tokenOut: ByteArray, errBuf: ByteArray, errLen: Int): Int
    fun wgbStats(handle: Int, buf: ByteArray, length: Int, errBuf: ByteArray, errLen: Int): Int
    fun wgbRebind(handle: Int): Int
    fun wgbStop(handle: Int)
    fun wgbLastError(buf: ByteArray, length: Int): Int
    fun wgbVersion(): Pointer?
}

internal const val PATH_PROPERTY = "terminalmax.wgbridge.path"
private const val RESOURCES_PROPERTY = "compose.application.resources.dir"
private const val ERR_LEN = 512
private const val STATS_LEN = 1024

internal fun nativeLibraryFileName(osName: String): String {
    val os = osName.lowercase()
    return when {
        os.contains("mac") || os.contains("darwin") -> "libwgbridge.dylib"
        os.contains("win") -> "wgbridge.dll"
        else -> "libwgbridge.so"
    }
}

/** The holder keeps the proxy (and with it the JNA library handle) reachable forever: never unloaded. */
private object LibraryHolder {
    private var lib: WgBridgeLib? = null

    @Synchronized
    fun get(): WgBridgeLib {
        lib?.let { return it }
        val loaded = load()
        lib = loaded
        return loaded
    }

    private fun load(): WgBridgeLib {
        try {
            val explicit = System.getProperty(PATH_PROPERTY)
            if (!explicit.isNullOrEmpty()) {
                val file = File(explicit)
                if (!file.isAbsolute || !file.isFile) {
                    throw WireGuardException("wgbridge: $PATH_PROPERTY must be an absolute path of an existing file")
                }
                return Native.load(file.path, WgBridgeLib::class.java)
            }
            val resources = System.getProperty(RESOURCES_PROPERTY)
            if (!resources.isNullOrEmpty()) {
                val file = File(resources, nativeLibraryFileName(System.getProperty("os.name") ?: ""))
                if (file.isFile) return Native.load(file.absolutePath, WgBridgeLib::class.java)
            }
            // Default JNA search: jna.library.path, the OS library path, the classpath.
            return Native.load("wgbridge", WgBridgeLib::class.java)
        } catch (e: UnsatisfiedLinkError) {
            throw WireGuardException("wgbridge: native library could not be loaded", e)
        }
    }
}

/** ASCII text up to the first NUL. */
private fun cString(buf: ByteArray, limit: Int = buf.size): String {
    var n = 0
    while (n < limit && n < buf.size && buf[n] != 0.toByte()) n++
    return String(buf, 0, n, Charsets.US_ASCII)
}

private class JnaWgNative(private val lib: WgBridgeLib) : WgNative {
    private fun fail(err: ByteArray, what: String, rc: Int): Nothing {
        val msg = cString(err)
        throw WireGuardException(if (msg.isEmpty()) "wgbridge: $what failed ($rc)" else msg)
    }

    override fun version(): String = lib.wgbVersion()?.getString(0, "US-ASCII") ?: "unknown"

    override fun start(config: ByteArray): Int {
        // NUL-terminated native copy; zeroed right after the call.
        val mem = Memory(config.size.toLong() + 1)
        try {
            mem.write(0, config, 0, config.size)
            mem.setByte(config.size.toLong(), 0)
            val err = ByteArray(ERR_LEN)
            val rc = lib.wgbStart(mem, err, err.size)
            if (rc <= 0) fail(err, "start", rc)
            return rc
        } finally {
            mem.clear()
            mem.close()
        }
    }

    override fun openForward(handle: Int, target: String, tokenOut: ByteArray): Int {
        val targetBytes = (target + "\u0000").toByteArray(Charsets.US_ASCII)
        val err = ByteArray(ERR_LEN)
        val rc = lib.wgbOpenForward(handle, targetBytes, tokenOut, err, err.size)
        if (rc <= 0) fail(err, "open forward", rc)
        return rc
    }

    override fun stats(handle: Int): String {
        val buf = ByteArray(STATS_LEN)
        val err = ByteArray(ERR_LEN)
        val rc = lib.wgbStats(handle, buf, buf.size, err, err.size)
        if (rc < 0) fail(err, "stats", rc)
        return cString(buf, rc)
    }

    override fun rebind(handle: Int) {
        val rc = lib.wgbRebind(handle)
        if (rc < 0) {
            val last = ByteArray(ERR_LEN)
            lib.wgbLastError(last, last.size)
            fail(last, "rebind", rc)
        }
    }

    override fun stop(handle: Int) = lib.wgbStop(handle)
}

actual fun createWireGuardBackend(): WireGuardBackend = NativeWireGuardBackend(JnaWgNative(LibraryHolder.get()))
