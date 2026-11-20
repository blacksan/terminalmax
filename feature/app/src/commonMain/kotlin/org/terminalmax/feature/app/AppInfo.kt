// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

object AppInfo {
    const val NAME = "TerminalMax"
    const val VERSION = "0.2.0-pre-alpha"
    const val LICENSE_ID = "GPL-3.0-or-later"
}

enum class ThemeMode(val label: String) { System("System"), Light("Light"), Dark("Dark") }
