// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

/** Pure-Kotlin xterm key encoder. */
object XtermKeyEncoder {
    private const val ESC = "\u001b"

    /** xterm modifier parameter: 1 + shift(1) + alt(2) + ctrl(4). 1 means "no modifier". */
    private fun param(m: KeyModifiers): Int =
        1 + (if (m.shift) 1 else 0) + (if (m.alt) 2 else 0) + (if (m.ctrl) 4 else 0)

    private fun hasMods(m: KeyModifiers) = m.shift || m.alt || m.ctrl

    fun encode(
        key: TerminalKey,
        modifiers: KeyModifiers = KeyModifiers.None,
        applicationCursorKeys: Boolean = false,
    ): ByteArray = encodeToString(key, modifiers, applicationCursorKeys).encodeToByteArray()

    fun encodeToString(
        key: TerminalKey,
        m: KeyModifiers = KeyModifiers.None,
        applicationCursorKeys: Boolean = false,
    ): String = when (key) {
        TerminalKey.Enter -> altPrefix(m, "\r")
        TerminalKey.Backspace -> altPrefix(m, if (m.ctrl) "\u0008" else "\u007f")
        TerminalKey.Tab -> if (m.shift) "$ESC[Z" else altPrefix(m, "\t")
        TerminalKey.Escape -> altPrefix(m, ESC)
        TerminalKey.Up -> cursorKey('A', m, applicationCursorKeys)
        TerminalKey.Down -> cursorKey('B', m, applicationCursorKeys)
        TerminalKey.Right -> cursorKey('C', m, applicationCursorKeys)
        TerminalKey.Left -> cursorKey('D', m, applicationCursorKeys)
        TerminalKey.Home -> cursorKey('H', m, applicationCursorKeys)
        TerminalKey.End -> cursorKey('F', m, applicationCursorKeys)
        TerminalKey.Insert -> tilde(2, m)
        TerminalKey.Delete -> tilde(3, m)
        TerminalKey.PageUp -> tilde(5, m)
        TerminalKey.PageDown -> tilde(6, m)
        TerminalKey.F1 -> ss3Function('P', m)
        TerminalKey.F2 -> ss3Function('Q', m)
        TerminalKey.F3 -> ss3Function('R', m)
        TerminalKey.F4 -> ss3Function('S', m)
        TerminalKey.F5 -> tilde(15, m)
        TerminalKey.F6 -> tilde(17, m)
        TerminalKey.F7 -> tilde(18, m)
        TerminalKey.F8 -> tilde(19, m)
        TerminalKey.F9 -> tilde(20, m)
        TerminalKey.F10 -> tilde(21, m)
        TerminalKey.F11 -> tilde(23, m)
        TerminalKey.F12 -> tilde(24, m)
    }

    private fun altPrefix(m: KeyModifiers, s: String) = if (m.alt) ESC + s else s

    private fun cursorKey(final: Char, m: KeyModifiers, app: Boolean): String = when {
        hasMods(m) -> "$ESC[1;${param(m)}$final"
        app -> "${ESC}O$final"
        else -> "$ESC[$final"
    }

    private fun tilde(code: Int, m: KeyModifiers): String =
        if (hasMods(m)) "$ESC[$code;${param(m)}~" else "$ESC[$code~"

    private fun ss3Function(final: Char, m: KeyModifiers): String =
        if (hasMods(m)) "$ESC[1;${param(m)}$final" else "${ESC}O$final"

    /**
     * Encodes a character. Ctrl+letter yields the C0 control code (Ctrl+C = 0x03), Alt adds an
     * ESC prefix. Returns null for code points that must not be sent: non-characters (U+FFFF,
     * U+FFFE, U+FDD0..FDEF, ...), surrogates, controls and DEL.
     *
     * With Ctrl, already-translated control codes (AWT delivers Ctrl+@ as 0 and Ctrl+\ ] ^ _ as
     * 0x1c..0x1f) are accepted, and Ctrl+8 -> 0x7f, Ctrl+` -> 0x00 follow xterm.
     */
    fun encodeCodePoint(codePoint: Int, m: KeyModifiers = KeyModifiers.None): ByteArray? {
        val cp = codePoint
        if (KeyboardInput.isNonCharacter(cp)) return null
        if (cp == 0 && !m.ctrl) return null
        val out = ArrayList<Byte>(8)
        if (m.alt) out.add(0x1b)
        if (m.ctrl) {
            val ctrl = when (cp) {
                in 'a'.code..'z'.code -> cp - 'a'.code + 1
                in 'A'.code..'Z'.code -> cp - 'A'.code + 1
                in 1..26 -> cp
                0, ' '.code, '@'.code, '2'.code, '`'.code -> 0
                '['.code, '3'.code -> 0x1b
                '\\'.code, '4'.code -> 0x1c
                ']'.code, '5'.code -> 0x1d
                '^'.code, '6'.code -> 0x1e
                '_'.code, '/'.code, '7'.code -> 0x1f
                in 0x1c..0x1f -> cp
                '8'.code, '?'.code -> 0x7f
                else -> -1
            }
            if (ctrl >= 0) {
                out.add(ctrl.toByte())
                return out.toByteArray()
            }
        }
        if (cp < 0x20 || cp == 0x7f) {
            // Raw control characters not covered above are not typed text.
            if (cp == 0x1b || cp == 0x09 || cp == 0x0d) out.add(cp.toByte()) else return null
            return out.toByteArray()
        }
        utf8Append(cp, out)
        return out.toByteArray()
    }

    private fun utf8Append(cp: Int, out: MutableList<Byte>) {
        when {
            cp < 0x80 -> out.add(cp.toByte())
            cp < 0x800 -> {
                out.add((0xC0 or (cp shr 6)).toByte())
                out.add((0x80 or (cp and 0x3F)).toByte())
            }
            cp < 0x10000 -> {
                out.add((0xE0 or (cp shr 12)).toByte())
                out.add((0x80 or ((cp shr 6) and 0x3F)).toByte())
                out.add((0x80 or (cp and 0x3F)).toByte())
            }
            else -> {
                out.add((0xF0 or (cp shr 18)).toByte())
                out.add((0x80 or ((cp shr 12) and 0x3F)).toByte())
                out.add((0x80 or ((cp shr 6) and 0x3F)).toByte())
                out.add((0x80 or (cp and 0x3F)).toByte())
            }
        }
    }
}
