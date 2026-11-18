// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.wireguard

import java.io.File
import java.io.IOException
import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions

/** Development switch: only with `-Dterminalmax.dev=true` may the library location be overridden. */
internal const val DEV_PROPERTY = "terminalmax.dev"

/** Absolute path of a bridge library; honoured only together with [DEV_PROPERTY]. */
internal const val PATH_PROPERTY = "terminalmax.wgbridge.path"

/** Set by the Compose Desktop launcher to `$APPDIR/resources` of the installed app. */
internal const val RESOURCES_PROPERTY = "compose.application.resources.dir"

internal fun isDevMode(): Boolean = System.getProperty(DEV_PROPERTY) == "true"

private fun isMac(os: String) = os.lowercase().let { it.contains("mac") || it.contains("darwin") }

private fun isWindows(os: String) = os.lowercase().startsWith("windows")

internal fun nativeLibraryFileName(osName: String): String = when {
    isMac(osName) -> "libwgbridge.dylib"
    isWindows(osName) -> "wgbridge.dll"
    else -> "libwgbridge.so"
}

/** File name of JNA's own native stub as it is looked up through `jna.boot.library.path`. */
internal fun jnaDispatchFileName(osName: String): String = when {
    isMac(osName) -> "libjnidispatch.jnilib"
    isWindows(osName) -> "jnidispatch.dll"
    else -> "libjnidispatch.so"
}

/**
 * Resolves [fileName] (a plain file name, never a path) inside the application's resources
 * directory [resourcesDir] and returns its real path. Throws [WireGuardException] unless
 * [resourcesDir] is an absolute existing directory and the file is a regular file (not a symbolic
 * link) whose canonical path lies inside the canonical resources directory.
 *
 * There is deliberately no fall-through to any search path.
 */
internal fun resolveBundledFile(resourcesDir: String?, fileName: String, what: String): File {
    if (resourcesDir.isNullOrEmpty()) {
        throw WireGuardException("wgbridge: $RESOURCES_PROPERTY is not set, the bundled $what cannot be located")
    }
    require(fileName.isNotEmpty() && fileName.none { it == '/' || it == '\\' } && fileName != "." && fileName != "..") {
        "fileName must be a plain file name"
    }
    try {
        val dir = File(resourcesDir)
        if (!dir.isAbsolute) throw WireGuardException("wgbridge: $RESOURCES_PROPERTY must be an absolute path")
        val root: Path = dir.toPath().toRealPath()
        if (!Files.isDirectory(root)) throw WireGuardException("wgbridge: $RESOURCES_PROPERTY is not a directory")
        val candidate: Path = root.resolve(fileName)
        if (!Files.isRegularFile(candidate, LinkOption.NOFOLLOW_LINKS)) {
            throw WireGuardException("wgbridge: bundled $what is missing for this platform ($fileName)")
        }
        val real: Path = candidate.toRealPath()
        if (!real.startsWith(root) || !Files.isRegularFile(real, LinkOption.NOFOLLOW_LINKS)) {
            throw WireGuardException("wgbridge: bundled $what is not inside the application resources")
        }
        return real.toFile()
    } catch (e: IOException) {
        throw WireGuardException("wgbridge: bundled $what cannot be accessed", e)
    } catch (e: SecurityException) {
        throw WireGuardException("wgbridge: bundled $what cannot be accessed", e)
    }
}

/** Development override ([PATH_PROPERTY]): an absolute path of an existing regular file. */
internal fun resolveDevLibrary(path: String): File {
    val file = File(path)
    if (!file.isAbsolute) throw WireGuardException("wgbridge: $PATH_PROPERTY must be an absolute path")
    try {
        val real = file.toPath().toRealPath()
        if (!Files.isRegularFile(real)) throw WireGuardException("wgbridge: $PATH_PROPERTY is not a regular file")
        return real.toFile()
    } catch (e: IOException) {
        throw WireGuardException("wgbridge: $PATH_PROPERTY does not name an existing file", e)
    }
}

/**
 * Points JNA at the bundled `jnidispatch` and forbids every other way of finding or extracting
 * it: no system library path (`jna.nosys`), no extraction to a temp directory (`jna.nounpack`),
 * no classpath fall-back (`jna.noclasspath`). If the bundled stub cannot be loaded JNA throws.
 *
 * All five properties are real in JNA 5.19.1 (`Native.loadNativeDispatchLibrary`). JNA reads them
 * once, in the static initialiser of `com.sun.jna.Native`, so this is only the FALLBACK for
 * `./gradlew run` and for processes that were not started by the packaged launcher: the packaged
 * launcher passes the same properties as JVM arguments (`desktopApp/build.gradle.kts`), and
 * [verifyJnaDispatchPath] proves after loading which stub JNA really uses.
 */
internal fun pinJnaDispatch(dispatch: File) {
    System.setProperty("jna.boot.library.path", dispatch.parentFile.path)
    System.setProperty("jna.boot.library.name", "jnidispatch")
    System.setProperty("jna.nosys", "true")
    System.setProperty("jna.nounpack", "true")
    System.setProperty("jna.noclasspath", "true")
}

/**
 * JNA sets the system property `jnidispatch.path` to the stub it loaded (only when it loaded one
 * from `jna.boot.library.path` or extracted one from the classpath, never for a system copy).
 * Fails closed unless that property names, after resolving links, exactly the bundled stub
 * [expected], which itself must lie inside [resourcesRoot]. This holds even if some other code
 * initialised JNA before this backend did.
 */
internal fun verifyJnaDispatchPath(jnidispatchPath: String?, expected: File, resourcesRoot: File) {
    if (jnidispatchPath.isNullOrEmpty()) {
        throw WireGuardException("wgbridge: JNA did not report which native stub it loaded; refusing to continue")
    }
    try {
        val actual = File(jnidispatchPath).toPath().toRealPath()
        val want = expected.toPath().toRealPath()
        val root = resourcesRoot.toPath().toRealPath()
        if (!want.startsWith(root)) {
            throw WireGuardException("wgbridge: the bundled JNA stub is not inside the application resources")
        }
        if (actual != want) {
            throw WireGuardException("wgbridge: JNA loaded a native stub other than the bundled one; refusing to continue")
        }
    } catch (e: IOException) {
        throw WireGuardException("wgbridge: the JNA native stub path cannot be verified", e)
    } catch (e: SecurityException) {
        throw WireGuardException("wgbridge: the JNA native stub path cannot be verified", e)
    }
}

/** Fails closed unless [actual] (the file JNA reports for the loaded bridge) is exactly [expected]. */
internal fun verifyLoadedLibraryFile(actual: File?, expected: File) {
    try {
        if (actual == null || actual.toPath().toRealPath() != expected.toPath().toRealPath()) {
            throw WireGuardException("wgbridge: the loaded bridge is not the resolved bundled file; refusing to continue")
        }
    } catch (e: IOException) {
        throw WireGuardException("wgbridge: the loaded bridge file cannot be verified", e)
    } catch (e: SecurityException) {
        throw WireGuardException("wgbridge: the loaded bridge file cannot be verified", e)
    }
}

/**
 * Development only: a private (owner-only) directory for JNA's extracted `jnidispatch`, instead
 * of the shared temp directory. Windows: `%LOCALAPPDATA%\TerminalMax\jna` (inherits the user-only
 * ACL of the profile). Elsewhere: a `0700` directory under the user's cache directory.
 */
internal fun privateJnaTmpDir(osName: String, env: Map<String, String>, userHome: String): File {
    try {
        if (isWindows(osName)) {
            val base = env["LOCALAPPDATA"]?.takeIf { it.isNotEmpty() }
                ?: throw WireGuardException("wgbridge: LOCALAPPDATA is not set")
            val dir = File(base, "TerminalMax" + File.separator + "jna")
            if (!dir.isAbsolute) throw WireGuardException("wgbridge: LOCALAPPDATA is not absolute")
            Files.createDirectories(dir.toPath())
            return dir
        }
        val cache = if (isMac(osName)) {
            File(userHome, "Library/Caches")
        } else {
            env["XDG_CACHE_HOME"]?.takeIf { it.startsWith("/") }?.let { File(it) } ?: File(userHome, ".cache")
        }
        if (!cache.isAbsolute) throw WireGuardException("wgbridge: the user's home directory is not absolute")
        val dir = File(cache, "terminalmax/jna")
        val path = dir.toPath()
        val ownerOnly = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
        Files.createDirectories(path.parent, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) Files.createDirectory(path, ownerOnly)
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
            throw WireGuardException("wgbridge: the JNA temp location is not a plain directory")
        }
        val me = FileSystems.getDefault().userPrincipalLookupService
            .lookupPrincipalByName(System.getProperty("user.name") ?: "")
        if (Files.getOwner(path, LinkOption.NOFOLLOW_LINKS) != me) {
            throw WireGuardException("wgbridge: the JNA temp directory is not owned by the current user")
        }
        val owner: Set<PosixFilePermission> = PosixFilePermissions.fromString("rwx------")
        if (Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS) != owner) {
            Files.setPosixFilePermissions(path, owner)
        }
        return dir
    } catch (e: IOException) {
        throw WireGuardException("wgbridge: cannot prepare a private JNA temp directory", e)
    } catch (e: UnsupportedOperationException) {
        throw WireGuardException("wgbridge: cannot prepare a private JNA temp directory", e)
    }
}
