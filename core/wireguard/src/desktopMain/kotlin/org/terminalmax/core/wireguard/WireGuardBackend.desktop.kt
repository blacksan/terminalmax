// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import com.sun.jna.Library
import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import com.sun.jna.Pointer
import java.io.File
import java.io.IOException

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

/**
 * What was actually loaded, for diagnostics and the packaged app's `--self-test`. Only exists after
 * a successful [createWireGuardBackend]; contains file paths only, never key material.
 */
class DesktopNativeInfo internal constructor(
    /** Real path of the application resources directory (null when the dev override is used). */
    val resourcesDir: String?,
    /** Real path of the bridge library that was loaded. */
    val bridgeLibrary: String,
    /** Real path of the JNA stub that was loaded and verified, or null (dev mode without a bundled stub). */
    val jnaDispatch: String?,
    /** Version of the JNA jar (`Native.VERSION`). */
    val jnaVersion: String,
    /** True if JNA had already been initialised by someone else before the backend was (see [verifyJnaDispatchPath]). */
    val jnaInitialisedBeforeBackend: Boolean,
)

/** The paths used by the loaded bridge, or null if [createWireGuardBackend] has not succeeded yet. */
fun desktopNativeInfo(): DesktopNativeInfo? = LibraryHolder.info

/** The holder keeps the proxy (and with it the JNA library handle) reachable forever: never unloaded. */
private object LibraryHolder {
    private var lib: WgBridgeLib? = null

    @Volatile
    var info: DesktopNativeInfo? = null
        private set

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
     * (`jna.boot.library.path`, `jna.nounpack`, `jna.nosys`, `jna.noclasspath`): nothing is
     * searched, nothing is extracted to a temp directory. There is no fall-back to the default JNA
     * search.
     *
     * The packaged launcher already passes these properties as JVM arguments, so they hold before
     * any class is loaded; setting them here is only the fallback for `./gradlew run`. Independent
     * of who initialised JNA first, after loading we require that the stub JNA reports
     * (`jnidispatch.path`) and the bridge file are exactly the bundled files, and fail closed
     * (the library is then never used) otherwise.
     *
     * Only with `-Dterminalmax.dev=true` may [PATH_PROPERTY] name another library (tests, the e2e
     * job, `./gradlew run`).
     */
    private fun load(): WgBridgeLib {
        val os = System.getProperty("os.name") ?: ""
        val dev = isDevMode()
        val explicit = System.getProperty(PATH_PROPERTY)
        // Read before anything below can initialise JNA.
        val jnaEarly = System.getProperty("jna.loaded") == "true"
        val library: File
        var dispatch: File? = null
        var root: File? = null
        if (!explicit.isNullOrEmpty()) {
            if (!dev) {
                throw WireGuardException("wgbridge: $PATH_PROPERTY is only honoured together with -D$DEV_PROPERTY=true")
            }
            library = resolveDevLibrary(explicit)
            useJnaDefaultsForDev(os)
        } else {
            val resources = System.getProperty(RESOURCES_PROPERTY)
            library = resolveBundledFile(resources, nativeLibraryFileName(os), "native library")
            root = try {
                File(resources!!).toPath().toRealPath().toFile()
            } catch (e: IOException) {
                throw WireGuardException("wgbridge: the application resources directory cannot be resolved", e)
            }
            dispatch = if (dev) {
                try {
                    resolveBundledFile(resources, jnaDispatchFileName(os), "JNA stub")
                } catch (_: WireGuardException) {
                    null
                }
            } else {
                resolveBundledFile(resources, jnaDispatchFileName(os), "JNA stub")
            }
            if (dispatch != null) pinJnaDispatch(dispatch) else useJnaDefaultsForDev(os)
        }
        val loaded = try {
            Native.load(library.path, WgBridgeLib::class.java)
        } catch (e: LinkageError) {
            throw WireGuardException("wgbridge: native library could not be loaded", e)
        }
        if (dispatch != null && root != null) {
            verifyJnaDispatchPath(System.getProperty("jnidispatch.path"), dispatch, root)
        }
        try {
            verifyLoadedLibraryFile(NativeLibrary.getInstance(library.path).file, library)
        } catch (e: LinkageError) {
            throw WireGuardException("wgbridge: the loaded bridge cannot be verified", e)
        }
        info = DesktopNativeInfo(root?.path, library.path, dispatch?.path, Native.VERSION, jnaEarly)
        return loaded
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
