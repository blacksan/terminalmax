// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import org.terminalmax.core.terminal.KeyModifiers
import org.terminalmax.core.terminal.TerminalKey

/** Keys of the row above the Android soft keyboard. Ctrl and Alt are sticky: they apply to the next key only. */
enum class ExtraKey(val label: String) {
    Esc("Esc"), Tab("Tab"), Ctrl("Ctrl"), Alt("Alt"),
    Left("←"), Down("↓"), Up("↑"), Right("→"),
    Home("Home"), End("End"), PageUp("PgUp"), PageDown("PgDn"),
    Pipe("|"), Dash("-"), Slash("/"),
    ;

    val isModifier: Boolean get() = this == Ctrl || this == Alt
}

/**
 * Bytes for typed [text] with the sticky modifiers applied to its first character: Ctrl turns ASCII letters and a
 * few symbols into control codes, Alt prefixes ESC. The rest of the text is sent unchanged.
 */
fun encodeTypedText(text: String, ctrl: Boolean, alt: Boolean): ByteArray {
    if (text.isEmpty()) return ByteArray(0)
    val normalized = text.replace("\r\n", "\r").replace('\n', '\r')
    if (!ctrl && !alt) return normalized.encodeToByteArray()
    val first = normalized[0]
    val rest = normalized.substring(1).encodeToByteArray()
    val head: ByteArray = if (ctrl && first.code < 0x80) {
        val code = controlCode(first)
        if (code != null) byteArrayOf(code.toByte()) else first.toString().encodeToByteArray()
    } else {
        first.toString().encodeToByteArray()
    }
    val prefixed = if (alt) byteArrayOf(0x1b) + head else head
    return prefixed + rest
}

private fun controlCode(c: Char): Int? = when (c) {
    in 'a'..'z' -> c.code - 'a'.code + 1
    in 'A'..'Z' -> c.code - 'A'.code + 1
    '@', ' ' -> 0
    '[' -> 27
    '\\' -> 28
    ']' -> 29
    '^' -> 30
    '_', '/' -> 31
    '?' -> 127
    else -> null
}

/**
 * Bytes for a key of the extra row, or null for the modifier keys (they only toggle state). [encodeKey] is the
 * terminal engine's key encoder, which knows the cursor-key mode.
 */
fun encodeExtraKey(
    key: ExtraKey,
    ctrl: Boolean,
    alt: Boolean,
    encodeKey: (TerminalKey, KeyModifiers) -> ByteArray,
): ByteArray? {
    val mods = KeyModifiers(ctrl = ctrl, alt = alt)
    return when (key) {
        ExtraKey.Ctrl, ExtraKey.Alt -> null
        ExtraKey.Esc -> encodeKey(TerminalKey.Escape, mods)
        ExtraKey.Tab -> encodeKey(TerminalKey.Tab, mods)
        ExtraKey.Left -> encodeKey(TerminalKey.Left, mods)
        ExtraKey.Down -> encodeKey(TerminalKey.Down, mods)
        ExtraKey.Up -> encodeKey(TerminalKey.Up, mods)
        ExtraKey.Right -> encodeKey(TerminalKey.Right, mods)
        ExtraKey.Home -> encodeKey(TerminalKey.Home, mods)
        ExtraKey.End -> encodeKey(TerminalKey.End, mods)
        ExtraKey.PageUp -> encodeKey(TerminalKey.PageUp, mods)
        ExtraKey.PageDown -> encodeKey(TerminalKey.PageDown, mods)
        ExtraKey.Pipe -> encodeTypedText("|", ctrl, alt)
        ExtraKey.Dash -> encodeTypedText("-", ctrl, alt)
        ExtraKey.Slash -> encodeTypedText("/", ctrl, alt)
    }
}
