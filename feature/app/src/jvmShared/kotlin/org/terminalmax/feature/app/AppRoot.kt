// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.focusable
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.terminalmax.core.designsystem.theme.AppTheme

/** Windows at least this wide get a navigation rail instead of the bottom bar. */
private val WIDE_BREAKPOINT = 720.dp

/** The whole app UI. Platform apps call this from their activity / window. */
@Composable
fun TerminalMaxApp(container: AppContainer) {
    val mode by container.prefs.themeMode.collectAsStateWithLifecycle()
    val dark = when (mode) {
        ThemeMode.System -> isSystemInDarkTheme()
        ThemeMode.Light -> false
        ThemeMode.Dark -> true
    }
    AppTheme(darkTheme = dark) {
        Surface(Modifier.fillMaxSize()) {
            val vault by container.vault.state.collectAsStateWithLifecycle()
            if (vault.phase == VaultPhase.Unlocked) MainShell(container) else VaultGateScreen(container.vault)
        }
    }
}

@Composable
private fun MainShell(container: AppContainer) {
    val nav = container.navigator
    val stack by nav.stack.collectAsStateWithLifecycle()
    val sessionCount by container.sessions.count.collectAsStateWithLifecycle()
    val current = stack.last()
    val root = stack.first()
    val focus = remember { FocusRequester() }

    container.platform.BackHandler(enabled = stack.size > 1) { nav.pop() }
    LaunchedEffect(Unit) { runCatching { focus.requestFocus() } }

    BoxWithConstraints(
        Modifier
            .fillMaxSize()
            // Desktop: Esc goes back (the terminal consumes Esc itself, so it never gets here from a session).
            .onKeyEvent { event ->
                if (event.type == KeyEventType.KeyDown && event.key == Key.Escape && stack.size > 1 && current !is Screen.Terminal) {
                    nav.pop()
                    true
                } else {
                    false
                }
            }
            .focusRequester(focus)
            .focusable(),
    ) {
        val wide = maxWidth >= WIDE_BREAKPOINT
        val showNav = wide || current in TopLevelScreens
        Scaffold(
            bottomBar = {
                if (!wide && showNav) {
                    NavigationBar {
                        TopLevelScreens.forEach { screen ->
                            NavigationBarItem(
                                selected = root == screen,
                                onClick = { nav.switchTo(screen) },
                                icon = { NavIcon(screen, sessionCount) },
                                label = { Text(screen.title()) },
                            )
                        }
                    }
                }
            },
        ) { padding ->
            Row(Modifier.padding(padding).fillMaxSize()) {
                if (wide && showNav) {
                    NavigationRail {
                        TopLevelScreens.forEach { screen ->
                            NavigationRailItem(
                                selected = root == screen,
                                onClick = { nav.switchTo(screen) },
                                icon = { NavIcon(screen, sessionCount) },
                                label = { Text(screen.title()) },
                            )
                        }
                    }
                }
                ScreenHost(container, current)
            }
        }
    }
}

@Composable
private fun NavIcon(screen: Screen, sessionCount: Int) {
    val glyph = when (screen) {
        Screen.Hosts -> "☰"
        Screen.WireGuard -> "⚿"
        Screen.Sessions -> ">_"
        else -> "⚙"
    }
    if (screen == Screen.Sessions && sessionCount > 0) {
        BadgedBox(badge = { Badge { Text(sessionCount.toString()) } }) { Text(glyph) }
    } else {
        Text(glyph)
    }
}

@Composable
private fun ScreenHost(container: AppContainer, screen: Screen) {
    when (screen) {
        Screen.Hosts -> HostListScreen(container)
        Screen.WireGuard -> WireGuardScreen(container)
        Screen.Sessions -> SessionsScreen(container)
        Screen.Settings -> SettingsScreen(container)
        is Screen.HostEditor -> HostEditorScreen(container, screen.hostId)
        Screen.SyncSettings -> SyncSettingsScreen(container)
        Screen.About -> AboutScreen(container)
        is Screen.Terminal -> TerminalScreen(container, screen.sessionId)
    }
}
