// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.desktop

import org.terminalmax.core.wireguard.createWireGuardBackend
import org.terminalmax.core.wireguard.desktopNativeInfo
import java.io.File

/**
 * `--self-test[=<result file>]`: loads the WireGuard backend exactly like the app does, prints the
 * bridge version and the resolved library paths, then `SELFTEST OK` and exits 0. Any failure prints
 * the error (`SELFTEST FAILED: ...`) and exits non-zero.
 *
 * The report is printed to stdout (stderr on failure) AND, when a path is given, written to that
 * file: a Windows GUI-subsystem launcher has no console, so CI asserts on the file. The report
 * contains file paths and version strings only, never key material or configuration.
 *
 * Only meaningful for the packaged app (or the `createDistributable` image): the launcher
 * arguments with `$APPDIR` are not expanded by `./gradlew run`.
 */
internal fun runSelfTest(resultFile: String?): Int {
    val report = StringBuilder()
    var ok = false
    try {
        // Proof that the PACKAGED launcher (not the loader's fallback) supplied the JNA pinning:
        // these must already hold before anything in this process has touched JNA.
        val launcher = listOf("jna.nosys", "jna.nounpack", "jna.noclasspath").map { it to System.getProperty(it) }
        launcher.forEach { (k, v) -> report.append("launcher $k=$v\n") }
        val bootPath = System.getProperty("jna.boot.library.path")
        val resources = System.getProperty("compose.application.resources.dir")
        report.append("launcher jna.boot.library.path=$bootPath\n")
        report.append("compose.application.resources.dir=$resources\n")
        check(System.getProperty("jna.loaded") != "true") { "JNA was initialised before the self-test started" }
        launcher.forEach { (k, v) -> check(v == "true") { "launcher did not set $k=true (got $v)" } }
        val boot = checkNotNull(bootPath?.takeIf { it.isNotEmpty() }) { "launcher did not set jna.boot.library.path" }
        val res = checkNotNull(resources?.takeIf { it.isNotEmpty() }) { "compose.application.resources.dir is not set" }
        check(File(boot).toPath().toRealPath() == File(res).toPath().toRealPath()) {
            "jna.boot.library.path ($boot) is not the application resources directory ($res)"
        }

        val backend = createWireGuardBackend()
        report.append("wgbridge version: ${backend.version()}\n")
        val info = checkNotNull(desktopNativeInfo()) { "no native-loading report after a successful load" }
        report.append("resources dir: ${info.resourcesDir}\n")
        report.append("bridge library: ${info.bridgeLibrary}\n")
        report.append("jna stub: ${info.jnaDispatch}\n")
        report.append("jna version: ${info.jnaVersion}\n")
        report.append("jna initialised before backend: ${info.jnaInitialisedBeforeBackend}\n")
        check(info.jnaDispatch != null) { "the JNA stub in use is not the bundled one" }
        ok = true
        report.append("SELFTEST OK\n")
    } catch (t: Throwable) {
        report.append("SELFTEST FAILED: ${t.javaClass.name}: ${t.message}\n")
        var cause = t.cause
        while (cause != null) {
            report.append("  caused by ${cause.javaClass.name}: ${cause.message}\n")
            cause = cause.cause
        }
    }
    val text = report.toString()
    (if (ok) System.out else System.err).print(text)
    (if (ok) System.out else System.err).flush()
    if (resultFile != null) {
        try {
            File(resultFile).writeText(text, Charsets.UTF_8)
        } catch (e: Exception) {
            System.err.println("SELFTEST FAILED: cannot write $resultFile: ${e.message}")
            return 3
        }
    }
    return if (ok) 0 else 1
}
