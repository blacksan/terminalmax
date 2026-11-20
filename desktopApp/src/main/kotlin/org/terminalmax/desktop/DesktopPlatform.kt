// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.desktop

import androidx.compose.runtime.Composable
import java.awt.FileDialog
import java.awt.Frame
import java.io.File
import org.terminalmax.feature.app.PlatformServices

/** Desktop implementation of the shared platform services. */
class DesktopPlatform : PlatformServices {
    private val osName = (System.getProperty("os.name") ?: "").lowercase()
    private val home = System.getProperty("user.home") ?: "."

    /** Where per-user application data lives: Application Support (macOS), %APPDATA% (Windows), XDG data dir (Linux). */
    private val dataRoot: File = when {
        osName.contains("mac") -> File(home, "Library/Application Support/TerminalMax")
        osName.contains("win") -> File(System.getenv("APPDATA")?.takeIf { it.isNotBlank() } ?: File(home, "AppData/Roaming").path, "TerminalMax")
        else -> File(System.getenv("XDG_DATA_HOME")?.takeIf { it.isNotBlank() } ?: File(home, ".local/share").path, "terminalmax")
    }

    override val vaultDirectory: File = File(dataRoot, "vault")
    override val prefsFile: File = File(dataRoot, "preferences.properties")
    override val isAndroid: Boolean = false

    override fun readLegalText(name: String): String? {
        val dir = System.getProperty("compose.application.resources.dir") ?: return null
        val file = File(dir, name)
        return try {
            if (file.isFile && file.length() < MAX_LEGAL_BYTES) file.readText() else null
        } catch (_: Exception) {
            null
        }
    }

    override fun pickTextFile(onResult: (String?) -> Unit) {
        Thread {
            val text = try {
                val dialog = FileDialog(null as Frame?, "Import WireGuard configuration", FileDialog.LOAD)
                dialog.isVisible = true
                val name = dialog.file
                val dir = dialog.directory
                if (name == null || dir == null) {
                    null
                } else {
                    val file = File(dir, name)
                    if (file.length() > MAX_IMPORT_BYTES) null else file.readText()
                }
            } catch (_: Exception) {
                null
            }
            onResult(text)
        }.apply { isDaemon = true }.start()
    }

    override fun saveFile(suggestedName: String, bytes: ByteArray, onResult: (Boolean) -> Unit) {
        Thread {
            val ok = try {
                val dialog = FileDialog(null as Frame?, "Save backup", FileDialog.SAVE)
                dialog.file = suggestedName
                dialog.isVisible = true
                val name = dialog.file
                val dir = dialog.directory
                if (name == null || dir == null) {
                    false
                } else {
                    File(dir, name).writeBytes(bytes)
                    true
                }
            } catch (_: Exception) {
                false
            }
            onResult(ok)
        }.apply { isDaemon = true }.start()
    }

    @Composable
    override fun BackHandler(enabled: Boolean, onBack: () -> Unit) {
        // The desktop goes back with the Esc key (handled by the shared shell).
    }

    private companion object {
        const val MAX_IMPORT_BYTES = 256 * 1024L
        const val MAX_LEGAL_BYTES = 2 * 1024 * 1024L
    }
}
