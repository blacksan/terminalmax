// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update

/** Typed navigation keys. A deliberately small replacement for Navigation 3 in this first release. */
sealed interface Screen {
    data object Hosts : Screen
    data object WireGuard : Screen
    data object Sessions : Screen
    data object Settings : Screen
    data class HostEditor(val hostId: String?) : Screen
    data object SyncSettings : Screen
    data object About : Screen
    data class Terminal(val sessionId: Long) : Screen
}

/** The four destinations shown in the bottom bar / navigation rail. */
val TopLevelScreens: List<Screen> = listOf(Screen.Hosts, Screen.WireGuard, Screen.Sessions, Screen.Settings)

fun Screen.title(): String = when (this) {
    Screen.Hosts -> "Hosts"
    Screen.WireGuard -> "WireGuard"
    Screen.Sessions -> "Sessions"
    Screen.Settings -> "Settings"
    is Screen.HostEditor -> if (hostId == null) "Add host" else "Edit host"
    Screen.SyncSettings -> "Sync"
    Screen.About -> "About"
    is Screen.Terminal -> "Terminal"
}

/** A back stack of [Screen] keys. The first entry is always a top-level screen. */
class Navigator(start: Screen = Screen.Hosts) {
    private val mutableStack = MutableStateFlow(listOf(start))

    val stack: StateFlow<List<Screen>> get() = mutableStack

    val current: Screen get() = mutableStack.value.last()

    val canGoBack: Boolean get() = mutableStack.value.size > 1

    fun push(screen: Screen) {
        mutableStack.update { if (it.last() == screen) it else it + screen }
    }

    /** Pops the top entry; returns false (and does nothing) at the root. */
    fun pop(): Boolean {
        var popped = false
        mutableStack.update {
            if (it.size > 1) {
                popped = true
                it.dropLast(1)
            } else {
                popped = false
                it
            }
        }
        return popped
    }

    /** Replaces the whole stack with one top-level screen. */
    fun switchTo(root: Screen) {
        mutableStack.value = listOf(root)
    }

    fun replaceTop(screen: Screen) {
        mutableStack.update { it.dropLast(1) + screen }
    }
}
