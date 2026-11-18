// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal.ui

import androidx.compose.ui.graphics.Color

/** 16 ANSI colours, default foreground/background and cursor colour; resolves the 256-colour palette. */
class TerminalPalette(
    val ansi: List<Color>,
    val foreground: Color,
    val background: Color,
    val cursor: Color,
) {
    init {
        require(ansi.size == 16) { "ANSI palette needs 16 colours" }
    }

    private val table: Array<Color> = Array(256) { i ->
        when {
            i < 16 -> ansi[i]
            i < 232 -> {
                val n = i - 16
                Color(CUBE_LEVELS[n / 36], CUBE_LEVELS[(n / 6) % 6], CUBE_LEVELS[n % 6])
            }
            else -> {
                val v = 8 + (i - 232) * 10
                Color(v, v, v)
            }
        }
    }

    /** Colour for palette index 0..255. */
    fun indexed(index: Int): Color = table[index.coerceIn(0, 255)]

    companion object {
        private val CUBE_LEVELS = intArrayOf(0, 95, 135, 175, 215, 255)

        /** xterm-like defaults on a dark background. */
        val Default = TerminalPalette(
            ansi = listOf(
                Color(0xFF000000), Color(0xFFCD0000), Color(0xFF00CD00), Color(0xFFCDCD00),
                Color(0xFF0000EE), Color(0xFFCD00CD), Color(0xFF00CDCD), Color(0xFFE5E5E5),
                Color(0xFF7F7F7F), Color(0xFFFF0000), Color(0xFF00FF00), Color(0xFFFFFF00),
                Color(0xFF5C5CFF), Color(0xFFFF00FF), Color(0xFF00FFFF), Color(0xFFFFFFFF),
            ),
            foreground = Color(0xFFE0E0E0),
            background = Color(0xFF101418),
            cursor = Color(0xFFE0E0E0),
        )
    }
}
