package org.terminalmax.core.designsystem.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialExpressiveTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.runtime.staticCompositionLocalOf

val LocalExtendedColors = staticCompositionLocalOf { TerminalMaxBrand.extended }

/**
 * App theme: Material 3 Expressive with the app brand.
 * Brand colours by default; [dynamicColor] = true follows the wallpaper on Android 12+.
 */
// If the CMP material3 artifact does not require this opt-in, remove it (see CI output).
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun AppTheme(
    brand: Brand = TerminalMaxBrand,
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = false,
    content: @Composable () -> Unit,
) {
    val colorScheme = (if (dynamicColor) platformDynamicColorScheme(darkTheme) else null)
        ?: if (darkTheme) brand.dark else brand.light

    CompositionLocalProvider(
        LocalExtendedColors provides if (darkTheme) brand.extendedDark else brand.extended,
    ) {
        MaterialExpressiveTheme(
            colorScheme = colorScheme,
            motionScheme = MotionScheme.expressive(),
            shapes = AppShapes,
            typography = AppTypography,
            content = content,
        )
    }
}

/** Extra colour roles: `AppTheme.extended.success` etc. */
object AppTheme {
    val extended: ExtendedColors
        @Composable @ReadOnlyComposable get() = LocalExtendedColors.current
}
