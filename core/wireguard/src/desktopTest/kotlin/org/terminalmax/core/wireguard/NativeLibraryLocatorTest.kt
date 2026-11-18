// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** The locator never touches JNA, so these run on every platform without the native library. */
class NativeLibraryLocatorTest {
    private fun tempDir(): File = Files.createTempDirectory("tmx-locator-test").toFile().also { it.deleteOnExit() }

    @Test
    fun missingOrEmptyResourcesDirIsAnError() {
        assertFailsWith<WireGuardException> { resolveBundledFile(null, "libwgbridge.so", "native library") }
        assertFailsWith<WireGuardException> { resolveBundledFile("", "libwgbridge.so", "native library") }
        assertFailsWith<WireGuardException> { resolveBundledFile("relative/dir", "libwgbridge.so", "native library") }
    }

    @Test
    fun missingBundledFileFailsInsteadOfFallingThrough() {
        val dir = tempDir()
        val e = assertFailsWith<WireGuardException> { resolveBundledFile(dir.path, "libwgbridge.so", "native library") }
        assertTrue(e.message!!.contains("missing"), e.message)
    }

    @Test
    fun directoryIsNotAcceptedAsLibrary() {
        val dir = tempDir()
        File(dir, "libwgbridge.so").mkdir()
        assertFailsWith<WireGuardException> { resolveBundledFile(dir.path, "libwgbridge.so", "native library") }
    }

    @Test
    fun regularFileInsideTheResourcesDirIsResolved() {
        val dir = tempDir()
        val lib = File(dir, "libwgbridge.so").apply { writeBytes(byteArrayOf(1)) }
        val found = resolveBundledFile(dir.path, "libwgbridge.so", "native library")
        assertEquals(lib.toPath().toRealPath().toFile(), found)
    }

    @Test
    fun symbolicLinkToAFileOutsideIsRejected() {
        val dir = tempDir()
        val outside = File(tempDir(), "evil.so").apply { writeBytes(byteArrayOf(1)) }
        try {
            Files.createSymbolicLink(File(dir, "libwgbridge.so").toPath(), outside.toPath())
        } catch (_: Exception) {
            return // symbolic links unavailable here (e.g. Windows without the privilege)
        }
        assertFailsWith<WireGuardException> { resolveBundledFile(dir.path, "libwgbridge.so", "native library") }
    }

    @Test
    fun fileNamesMustBePlain() {
        val dir = tempDir()
        assertFailsWith<IllegalArgumentException> { resolveBundledFile(dir.path, "../libwgbridge.so", "x") }
        assertFailsWith<IllegalArgumentException> { resolveBundledFile(dir.path, "..", "x") }
    }

    @Test
    fun devLibraryMustBeAbsoluteAndExisting() {
        assertFailsWith<WireGuardException> { resolveDevLibrary("libwgbridge.so") }
        assertFailsWith<WireGuardException> { resolveDevLibrary(File(tempDir(), "nope.so").path) }
        val lib = File(tempDir(), "x.so").apply { writeBytes(byteArrayOf(1)) }
        assertEquals(lib.toPath().toRealPath().toFile(), resolveDevLibrary(lib.path))
    }

    @Test
    fun jnaStubFileNameByOs() {
        assertEquals("libjnidispatch.jnilib", jnaDispatchFileName("Mac OS X"))
        assertEquals("jnidispatch.dll", jnaDispatchFileName("Windows 11"))
        assertEquals("libjnidispatch.so", jnaDispatchFileName("Linux"))
    }

    @Test
    fun privateJnaTmpDirIsOwnerOnlyOnPosix() {
        if (System.getProperty("os.name").lowercase().startsWith("windows")) return
        val home = tempDir()
        val dir = privateJnaTmpDir("Linux", emptyMap(), home.path)
        assertTrue(dir.isDirectory)
        val perms = java.nio.file.Files.getPosixFilePermissions(dir.toPath())
        assertEquals(java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"), perms)
        // Idempotent.
        assertEquals(dir, privateJnaTmpDir("Linux", emptyMap(), home.path))
    }

    private fun withProperties(vararg pairs: Pair<String, String?>, block: () -> Unit) {
        val saved = pairs.map { (k, _) -> k to System.getProperty(k) }
        try {
            pairs.forEach { (k, v) -> if (v == null) System.clearProperty(k) else System.setProperty(k, v) }
            block()
        } finally {
            saved.forEach { (k, v) -> if (v == null) System.clearProperty(k) else System.setProperty(k, v) }
        }
    }

    @Test
    fun packagedModeNeverFallsBackToTheJnaSearchPath() {
        val os = System.getProperty("os.name") ?: ""
        val planted = tempDir().also { File(it, nativeLibraryFileName(os)).writeBytes(byteArrayOf(1)) }
        withProperties(
            RESOURCES_PROPERTY to null,
            DEV_PROPERTY to null,
            PATH_PROPERTY to null,
            "jna.library.path" to planted.path,
        ) {
            assertFailsWith<WireGuardException> { createWireGuardBackend() }
        }
    }

    @Test
    fun explicitLibraryPathIsIgnoredWithoutTheDevFlag() {
        val os = System.getProperty("os.name") ?: ""
        val lib = File(tempDir(), nativeLibraryFileName(os)).apply { writeBytes(byteArrayOf(1)) }
        withProperties(RESOURCES_PROPERTY to null, DEV_PROPERTY to null, PATH_PROPERTY to lib.path) {
            val e = assertFailsWith<WireGuardException> { createWireGuardBackend() }
            assertTrue(e.message!!.contains(DEV_PROPERTY), e.message)
        }
    }
}
