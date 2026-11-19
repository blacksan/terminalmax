// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import androidx.compose.runtime.Composable
import java.io.File
import java.util.Properties
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** What each platform (Android app, desktop app) supplies to the shared UI. */
interface PlatformServices {
    /** Directory of the vault (see `VaultSession`). Must be inside the user's private/profile storage. */
    val vaultDirectory: File

    /** File for non-secret device preferences (theme, font size, auto-sync switch). */
    val prefsFile: File

    /** True on Android: soft keyboard with an extra-keys row, auto-lock after time in the background. */
    val isAndroid: Boolean

    val appVersion: String get() = AppInfo.VERSION

    /** Text of a bundled legal file (`LICENSE`, `THIRD_PARTY_NOTICES.md`), or null if this build does not have it. */
    fun readLegalText(name: String): String?

    /** Lets the user choose a small text file; [onResult] gets its text, or null if cancelled or unreadable. */
    fun pickTextFile(onResult: (String?) -> Unit)

    /** Lets the user save [bytes] under [suggestedName]; [onResult] says whether it was written. */
    fun saveFile(suggestedName: String, bytes: ByteArray, onResult: (Boolean) -> Unit)

    /** Back gesture / button handling (predictive back on Android; the desktop uses the Esc key instead). */
    @Composable
    fun BackHandler(enabled: Boolean, onBack: () -> Unit)
}

/** Device preferences. They hold nothing secret, so they live outside the vault. */
class AppPrefs(private val file: File?) {
    private val theme = MutableStateFlow(ThemeMode.System)
    private val fontSize = MutableStateFlow(DEFAULT_FONT_SP)
    private val autoSyncFlag = MutableStateFlow(false)

    val themeMode: StateFlow<ThemeMode> get() = theme
    val terminalFontSp: StateFlow<Int> get() = fontSize
    val autoSync: StateFlow<Boolean> get() = autoSyncFlag

    init {
        load()
    }

    fun setThemeMode(mode: ThemeMode) {
        theme.value = mode
        save()
    }

    fun setTerminalFontSp(sp: Int) {
        fontSize.value = sp.coerceIn(MIN_FONT_SP, MAX_FONT_SP)
        save()
    }

    fun setAutoSync(enabled: Boolean) {
        autoSyncFlag.value = enabled
        save()
    }

    private fun load() {
        val f = file ?: return
        try {
            if (!f.isFile) return
            val p = Properties()
            f.inputStream().use { p.load(it) }
            theme.value = ThemeMode.entries.firstOrNull { it.name == p.getProperty("theme") } ?: ThemeMode.System
            fontSize.value = (p.getProperty("fontSp")?.toIntOrNull() ?: DEFAULT_FONT_SP).coerceIn(MIN_FONT_SP, MAX_FONT_SP)
            autoSyncFlag.value = p.getProperty("autoSync") == "true"
        } catch (_: Exception) {
            // Unreadable preferences fall back to the defaults.
        }
    }

    private fun save() {
        val f = file ?: return
        try {
            f.parentFile?.mkdirs()
            val p = Properties()
            p.setProperty("theme", theme.value.name)
            p.setProperty("fontSp", fontSize.value.toString())
            p.setProperty("autoSync", autoSyncFlag.value.toString())
            f.outputStream().use { p.store(it, "TerminalMax device preferences") }
        } catch (_: Exception) {
            // Preferences are best effort.
        }
    }

    companion object {
        const val DEFAULT_FONT_SP = 14
        const val MIN_FONT_SP = 8
        const val MAX_FONT_SP = 28
    }
}
