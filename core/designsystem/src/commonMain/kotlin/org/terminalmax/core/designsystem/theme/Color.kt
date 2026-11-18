package org.terminalmax.core.designsystem.theme

import androidx.compose.material3.ColorScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Immutable
import androidx.compose.ui.graphics.Color

/** Brand definition: one per app. */
@Immutable
data class Brand(
    val name: String,
    val light: ColorScheme,
    val dark: ColorScheme,
    val extended: ExtendedColors,
    val extendedDark: ExtendedColors,
)

/** Roles Material 3 does not have (status colours). */
@Immutable
data class ExtendedColors(
    val success: Color,
    val onSuccess: Color,
    val successContainer: Color,
    val onSuccessContainer: Color,
    val warning: Color,
    val onWarning: Color,
    val warningContainer: Color,
    val onWarningContainer: Color,
)

// TerminalMax brand: terminal green (seed ~#2E7D32) on near-black green surfaces (~#0E1512).
val TerminalMaxBrand = Brand(
    name = "TerminalMax",
    light = lightColorScheme(
        primary = Color(0xFF296B2F), onPrimary = Color(0xFFFFFFFF),
        primaryContainer = Color(0xFFB1F3AB), onPrimaryContainer = Color(0xFF002105),
        inversePrimary = Color(0xFF96D78F),
        secondary = Color(0xFF53634F), onSecondary = Color(0xFFFFFFFF),
        secondaryContainer = Color(0xFFD6E8CF), onSecondaryContainer = Color(0xFF111F0F),
        tertiary = Color(0xFF39656B), onTertiary = Color(0xFFFFFFFF),
        tertiaryContainer = Color(0xFFBCEBF2), onTertiaryContainer = Color(0xFF001F23),
        error = Color(0xFFBA1A1A), onError = Color(0xFFFFFFFF),
        errorContainer = Color(0xFFFFDAD6), onErrorContainer = Color(0xFF410002),
        background = Color(0xFFF5FBF1), onBackground = Color(0xFF171D16),
        surface = Color(0xFFF5FBF1), onSurface = Color(0xFF171D16),
        surfaceVariant = Color(0xFFDDE5D8), onSurfaceVariant = Color(0xFF41493F),
        surfaceTint = Color(0xFF296B2F),
        inverseSurface = Color(0xFF2C322B), inverseOnSurface = Color(0xFFECF3E8),
        outline = Color(0xFF727970), outlineVariant = Color(0xFFC1C9BC),
        scrim = Color(0xFF000000),
        surfaceBright = Color(0xFFF5FBF1), surfaceDim = Color(0xFFD5DCD1),
        surfaceContainerLowest = Color(0xFFFFFFFF), surfaceContainerLow = Color(0xFFEFF6EB),
        surfaceContainer = Color(0xFFEAF0E6), surfaceContainerHigh = Color(0xFFE4EAE0),
        surfaceContainerHighest = Color(0xFFDEE5DB),
    ),
    dark = darkColorScheme(
        primary = Color(0xFF96D78F), onPrimary = Color(0xFF00390C),
        primaryContainer = Color(0xFF0B5219), onPrimaryContainer = Color(0xFFB1F3AB),
        inversePrimary = Color(0xFF296B2F),
        secondary = Color(0xFFBACCB3), onSecondary = Color(0xFF253423),
        secondaryContainer = Color(0xFF3B4B38), onSecondaryContainer = Color(0xFFD6E8CF),
        tertiary = Color(0xFFA1CED5), onTertiary = Color(0xFF00363C),
        tertiaryContainer = Color(0xFF1F4D53), onTertiaryContainer = Color(0xFFBCEBF2),
        error = Color(0xFFFFB4AB), onError = Color(0xFF690005),
        errorContainer = Color(0xFF93000A), onErrorContainer = Color(0xFFFFDAD6),
        background = Color(0xFF0E1512), onBackground = Color(0xFFDEE4DC),
        surface = Color(0xFF0E1512), onSurface = Color(0xFFDEE4DC),
        surfaceVariant = Color(0xFF3F4A40), onSurfaceVariant = Color(0xFFBFC9BD),
        surfaceTint = Color(0xFF96D78F),
        inverseSurface = Color(0xFFDEE4DC), inverseOnSurface = Color(0xFF2B322E),
        outline = Color(0xFF899389), outlineVariant = Color(0xFF3F4A40),
        scrim = Color(0xFF000000),
        surfaceBright = Color(0xFF343B37), surfaceDim = Color(0xFF0E1512),
        surfaceContainerLowest = Color(0xFF090F0D), surfaceContainerLow = Color(0xFF161D1A),
        surfaceContainer = Color(0xFF1A211E), surfaceContainerHigh = Color(0xFF252C28),
        surfaceContainerHighest = Color(0xFF303733),
    ),
    extended = ExtendedColors(
        success = Color(0xFF1B6D2F), onSuccess = Color(0xFFFFFFFF),
        successContainer = Color(0xFFA6F5A9), onSuccessContainer = Color(0xFF002108),
        warning = Color(0xFF7A5900), onWarning = Color(0xFFFFFFFF),
        warningContainer = Color(0xFFFFDF9E), onWarningContainer = Color(0xFF261A00),
    ),
    extendedDark = ExtendedColors(
        success = Color(0xFF8BD88F), onSuccess = Color(0xFF003914),
        successContainer = Color(0xFF005320), onSuccessContainer = Color(0xFFA6F5A9),
        warning = Color(0xFFF6BE36), onWarning = Color(0xFF402D00),
        warningContainer = Color(0xFF5C4200), onWarningContainer = Color(0xFFFFDF9E),
    ),
)
