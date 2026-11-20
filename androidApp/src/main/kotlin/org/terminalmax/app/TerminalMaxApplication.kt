// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.app

import android.app.Application
import android.content.Intent
import androidx.core.content.ContextCompat
import kotlinx.coroutines.launch
import org.terminalmax.feature.app.AppContainer

class TerminalMaxApplication : Application() {
    lateinit var platform: AndroidPlatform
        private set
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        platform = AndroidPlatform(this)
        container = AppContainer(platform)
        // The foreground service exists exactly while at least one terminal session is open.
        container.scope.launch {
            container.sessions.count.collect { count ->
                if (count > 0) {
                    try {
                        ContextCompat.startForegroundService(this@TerminalMaxApplication, Intent(this@TerminalMaxApplication, SessionService::class.java))
                    } catch (_: Exception) {
                        // Starting a foreground service can be refused when the app is not allowed to; sessions still work.
                    }
                }
            }
        }
    }
}
