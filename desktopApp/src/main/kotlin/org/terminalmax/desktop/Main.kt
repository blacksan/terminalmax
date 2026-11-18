// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import org.terminalmax.core.designsystem.theme.AppTheme
import org.terminalmax.feature.proof.ProofScreen
import kotlin.system.exitProcess

private const val SELF_TEST_FLAG = "--self-test"

fun main(args: Array<String>) {
    // Handled before any window, Compose or AWT class is touched: this is the CI smoke test of the
    // PACKAGED app (JNA stub and bridge are found and loaded from the installed resources).
    val selfTest = args.firstOrNull { it == SELF_TEST_FLAG || it.startsWith("$SELF_TEST_FLAG=") }
    if (selfTest != null) {
        exitProcess(runSelfTest(selfTest.substringAfter('=', "").takeIf { it.isNotEmpty() }))
    }
    application {
        Window(onCloseRequest = ::exitApplication, title = "TerminalMax") {
            AppTheme {
                ProofScreen()
            }
        }
    }
}
