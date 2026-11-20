// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.unit.DpSize
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.rememberWindowState
import org.terminalmax.feature.app.AppContainer
import org.terminalmax.feature.app.TerminalMaxApp
import kotlin.system.exitProcess

private const val SELF_TEST_FLAG = "--self-test"

fun main(args: Array<String>) {
    // Handled before any window, Compose or AWT class is touched: this is the CI smoke test of the
    // PACKAGED app (JNA stub and bridge are found and loaded from the installed resources).
    val selfTest = args.firstOrNull { it == SELF_TEST_FLAG || it.startsWith("$SELF_TEST_FLAG=") }
    if (selfTest != null) {
        exitProcess(runSelfTest(selfTest.substringAfter('=', "").takeIf { it.isNotEmpty() }))
    }
    val container = AppContainer(DesktopPlatform())
    application {
        Window(
            onCloseRequest = {
                container.sessions.closeAll()
                container.vault.lock()
                exitApplication()
            },
            title = "TerminalMax",
            state = rememberWindowState(size = DpSize(1100.dp, 750.dp)),
        ) {
            TerminalMaxApp(container)
        }
    }
}
