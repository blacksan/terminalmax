package org.terminalmax.desktop

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import org.terminalmax.core.designsystem.theme.AppTheme
import org.terminalmax.feature.proof.ProofScreen

fun main() = application {
    Window(onCloseRequest = ::exitApplication, title = "TerminalMax") {
        AppTheme {
            ProofScreen()
        }
    }
}
