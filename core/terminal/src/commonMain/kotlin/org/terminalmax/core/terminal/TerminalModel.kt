// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

/** Engine-neutral colour of a terminal cell. */
sealed interface TerminalColor {
    /** The terminal's default foreground/background. */
    data object Default : TerminalColor

    /** An entry of the 256-colour palette (0..15 ANSI, 16..231 cube, 232..255 grey ramp). */
    data class Indexed(val index: Int) : TerminalColor {
        init {
            require(index in 0..255) { "Palette index out of range: $index" }
        }
    }

    /** A 24-bit colour. */
    data class Rgb(val r: Int, val g: Int, val b: Int) : TerminalColor {
        init {
            require(r in 0..255 && g in 0..255 && b in 0..255) { "RGB component out of range" }
        }
    }
}

data class CellStyle(
    val fg: TerminalColor = TerminalColor.Default,
    val bg: TerminalColor = TerminalColor.Default,
    val bold: Boolean = false,
    val italic: Boolean = false,
    val underline: Boolean = false,
    val inverse: Boolean = false,
    val dim: Boolean = false,
    val strikethrough: Boolean = false,
) {
    companion object {
        val Default = CellStyle()
    }
}

/**
 * One grid cell. [text] is a single grapheme/code point ("" for the right half of a wide
 * character, whose [width] is 0). A wide character has [width] 2 and is followed by a
 * placeholder cell.
 */
data class Cell(
    val text: String,
    val style: CellStyle = CellStyle.Default,
    val width: Int = 1,
) {
    companion object {
        val Blank = Cell(" ")
    }
}

/** Immutable copy of the visible screen. */
class TerminalSnapshot(
    val cols: Int,
    val rows: Int,
    /** [rows] lists of exactly [cols] cells. */
    val lines: List<List<Cell>>,
    val cursorCol: Int,
    val cursorRow: Int,
    val cursorVisible: Boolean,
    val title: String?,
    /** Number of lines currently held in scrollback (not part of [lines]). */
    val scrollbackSize: Int,
    val alternateScreen: Boolean = false,
) {
    /** Visible text of [row] with trailing blanks removed. */
    fun rowText(row: Int): String {
        val sb = StringBuilder()
        for (cell in lines[row]) if (cell.width > 0) sb.append(cell.text)
        return sb.toString().trimEnd()
    }
}

enum class TerminalKey {
    Enter, Backspace, Tab, Escape,
    Up, Down, Left, Right,
    Home, End, PageUp, PageDown, Insert, Delete,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
}

data class KeyModifiers(
    val ctrl: Boolean = false,
    val alt: Boolean = false,
    val shift: Boolean = false,
) {
    companion object {
        val None = KeyModifiers()
    }
}
