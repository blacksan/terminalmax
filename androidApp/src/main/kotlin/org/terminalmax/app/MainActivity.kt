// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.app

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import org.terminalmax.feature.app.TerminalMaxApp

class MainActivity : ComponentActivity() {
    private var stoppedAt = 0L

    private val notificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* the service works without it */ }

    private val openDocument =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> platform().onPicked(uri) }

    private val createDocument =
        registerForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
            platform().onSaveTarget(uri)
        }

    private fun app() = application as TerminalMaxApplication

    private fun platform() = app().platform

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        val p = platform()
        p.launchPicker = { openDocument.launch(arrayOf("*/*")) }
        p.launchSaver = { name -> createDocument.launch(name) }
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        val container = app().container
        setContent { TerminalMaxApp(container) }
    }

    override fun onStop() {
        super.onStop()
        stoppedAt = SystemClock.elapsedRealtime()
    }

    override fun onStart() {
        super.onStart()
        // Auto-lock after 5 minutes in the background, unless sessions are open (they keep running on purpose).
        val container = app().container
        if (stoppedAt != 0L &&
            SystemClock.elapsedRealtime() - stoppedAt > AUTO_LOCK_MILLIS &&
            container.sessions.count.value == 0
        ) {
            container.vault.lock()
        }
        stoppedAt = 0L
    }

    override fun onDestroy() {
        val p = platform()
        p.launchPicker = null
        p.launchSaver = null
        super.onDestroy()
    }

    private companion object {
        const val AUTO_LOCK_MILLIS = 5 * 60 * 1000L
    }
}
