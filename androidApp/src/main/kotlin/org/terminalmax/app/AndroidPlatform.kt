// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.app

import android.app.Application
import android.net.Uri
import androidx.compose.runtime.Composable
import java.io.File
import org.terminalmax.feature.app.PlatformServices

/** Android implementation of the shared platform services. The activity attaches its file launchers. */
class AndroidPlatform(private val app: Application) : PlatformServices {
    override val vaultDirectory: File = File(app.filesDir, "vault")
    override val prefsFile: File = File(app.filesDir, "preferences.properties")
    override val isAndroid: Boolean = true

    @Volatile
    private var pickCallback: ((String?) -> Unit)? = null

    @Volatile
    private var saveCallback: ((Boolean) -> Unit)? = null

    @Volatile
    private var pendingSave: ByteArray? = null

    /** Set by [MainActivity] while it is alive. */
    @Volatile
    var launchPicker: (() -> Unit)? = null

    @Volatile
    var launchSaver: ((String) -> Unit)? = null

    override fun readLegalText(name: String): String? = try {
        app.assets.open(name).bufferedReader().use { it.readText() }
    } catch (_: Exception) {
        null
    }

    override fun pickTextFile(onResult: (String?) -> Unit) {
        val launcher = launchPicker
        if (launcher == null) {
            onResult(null)
            return
        }
        pickCallback = onResult
        launcher()
    }

    override fun saveFile(suggestedName: String, bytes: ByteArray, onResult: (Boolean) -> Unit) {
        val launcher = launchSaver
        if (launcher == null) {
            onResult(false)
            return
        }
        pendingSave = bytes
        saveCallback = onResult
        launcher(suggestedName)
    }

    @Composable
    override fun BackHandler(enabled: Boolean, onBack: () -> Unit) {
        androidx.activity.compose.BackHandler(enabled = enabled, onBack = onBack)
    }

    fun onPicked(uri: Uri?) {
        val cb = pickCallback
        pickCallback = null
        if (cb == null) return
        if (uri == null) {
            cb(null)
            return
        }
        val text = try {
            app.contentResolver.openInputStream(uri)?.use { input ->
                val out = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                var total = 0
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    total += n
                    if (total > MAX_IMPORT_BYTES) return@use null
                    out.write(buffer, 0, n)
                }
                String(out.toByteArray(), Charsets.UTF_8)
            }
        } catch (_: Exception) {
            null
        }
        cb(text)
    }

    fun onSaveTarget(uri: Uri?) {
        val cb = saveCallback
        val bytes = pendingSave
        saveCallback = null
        pendingSave = null
        if (cb == null) return
        if (uri == null || bytes == null) {
            cb(false)
            return
        }
        val ok = try {
            app.contentResolver.openOutputStream(uri)?.use { it.write(bytes) } != null
        } catch (_: Exception) {
            false
        }
        cb(ok)
    }

    private companion object {
        const val MAX_IMPORT_BYTES = 256 * 1024
    }
}
