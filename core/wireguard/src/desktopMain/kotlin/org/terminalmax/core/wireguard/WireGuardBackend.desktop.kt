// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import java.io.File

/**
 * The C ABI exactly as exported by native/wgbridge/cmd/libwgbridge/main.go. `char *` parameters
 * without secrets are byte arrays (JNA copies them in and back out); the config and the forwarder
 * token buffer are native [Pointer]s (JNA `Memory`) so that they can be zeroed after use.
 */
internal interface WgBridgeLib : Library {
    fun wgbStart(confText: Pointer, errBuf: ByteArray, errLen: Int): Int
    fun wgbOpenForward(handle: Int, target: ByteArray, tokenOut: Pointer, errBuf: ByteArray, errLen: Int): Int
    fun wgbStats(handle: Int, buf: ByteArray, length: Int, errBuf: ByteArray, errLen: Int): Int
    fun wgbRebind(handle: Int): Int
    fun wgbStop(handle: Int)
    fun wgbLastError(buf: ByteArray, length: Int): Int
    fun wgbVersion(): Pointer?
}

private const val ERR_LEN = 512
private const val STATS_LEN = 1024

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

    /**
     * Packaged builds load the bridge ONLY from an absolute path inside the application's resources
     * directory ([RESOURCES_PROPERTY]) and pin JNA's own native stub to the copy bundled next to it
     * (`jna.boot.library.path`, `jna.nounpack`, `jna.nosys`): nothing is searched, nothing is
     * extracted to a temp directory. There is no fall-back to the default JNA search.
     *
     * Only with `-Dterminalmax.dev=true` may [PATH_PROPERTY] name another library (tests, the e2e
     * job, `./gradlew run`). JNA properties are set here, before the first JNA class is
     * initialised, so this must be the first JNA user in the process.
     */
    private fun load(): WgBridgeLib {
        val os = System.getProperty("os.name") ?: ""
        val dev = isDevMode()
        val explicit = System.getProperty(PATH_PROPERTY)
        val library: File
        if (!explicit.isNullOrEmpty()) {
            if (!dev) {
                throw WireGuardException("wgbridge: $PATH_PROPERTY is only honoured together with -D$DEV_PROPERTY=true")
            }
            library = resolveDevLibrary(explicit)
            useJnaDefaultsForDev(os)
        } else {
            val resources = System.getProperty(RESOURCES_PROPERTY)
            library = resolveBundledFile(resources, nativeLibraryFileName(os), "native library")
            if (dev) {
                val dispatch = try {
                    resolveBundledFile(resources, jnaDispatchFileName(os), "JNA stub")
                } catch (_: WireGuardException) {
                    null
                }
                if (dispatch != null) pinJnaDispatch(dispatch) else useJnaDefaultsForDev(os)
            } else {
                pinJnaDispatch(resolveBundledFile(resources, jnaDispatchFileName(os), "JNA stub"))
            }
        }
        try {
            return Native.load(library.path, WgBridgeLib::class.java)
        } catch (e: LinkageError) {
            throw WireGuardException("wgbridge: native library could not be loaded", e)
        }
    }

    /** Dev mode without a bundled JNA stub: let JNA extract it, but into a private directory. */
    private fun useJnaDefaultsForDev(os: String) {
        if (System.getProperty("jna.tmpdir").isNullOrEmpty()) {
            System.setProperty(
                "jna.tmpdir",
                privateJnaTmpDir(os, System.getenv(), System.getProperty("user.home") ?: "").path,
            )
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
        // JNA would copy a ByteArray argument through a temporary native buffer that it frees without
        // zeroing; a Memory block is wiped explicitly.
        val tokenMem = Memory(tokenOut.size.toLong())
        try {
            tokenMem.clear()
            val rc = lib.wgbOpenForward(handle, targetBytes, tokenMem, err, err.size)
            if (rc <= 0) fail(err, "open forward", rc)
            tokenMem.read(0, tokenOut, 0, tokenOut.size)
            return rc
        } finally {
            tokenMem.clear()
            tokenMem.close()
        }
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
