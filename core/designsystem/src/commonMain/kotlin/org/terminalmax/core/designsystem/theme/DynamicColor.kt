package org.terminalmax.core.designsystem.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.runtime.Composable

/** Wallpaper-based (Material You) colours. Android 12+ only; null elsewhere. */
@Composable
expect fun platformDynamicColorScheme(darkTheme: Boolean): ColorScheme?
