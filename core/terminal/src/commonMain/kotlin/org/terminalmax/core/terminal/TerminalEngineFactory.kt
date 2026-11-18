// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

/** Creates the platform's [TerminalEngine] (the same JediTerm-backed implementation on both targets). */
expect fun createTerminalEngine(cols: Int, rows: Int, scrollbackLines: Int = 5000): TerminalEngine
