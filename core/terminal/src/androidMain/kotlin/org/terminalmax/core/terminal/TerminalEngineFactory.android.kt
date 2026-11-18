// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

actual fun createTerminalEngine(cols: Int, rows: Int, scrollbackLines: Int): TerminalEngine =
    JediTermEngine(cols, rows, scrollbackLines)
