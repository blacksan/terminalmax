// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNull

class XtermKeyEncoderTest {
    private fun str(key: TerminalKey, m: KeyModifiers = KeyModifiers.None, app: Boolean = false) =
        XtermKeyEncoder.encodeToString(key, m, app)

    @Test
    fun arrowsNormalMode() {
        assertEquals("\u001b[A", str(TerminalKey.Up))
        assertEquals("\u001b[B", str(TerminalKey.Down))
        assertEquals("\u001b[C", str(TerminalKey.Right))
        assertEquals("\u001b[D", str(TerminalKey.Left))
    }

    @Test
    fun arrowsApplicationMode() {
        assertEquals("\u001bOA", str(TerminalKey.Up, app = true))
        assertEquals("\u001bOD", str(TerminalKey.Left, app = true))
    }

    @Test
    fun modifiedArrowUsesCsiParameter() {
        assertEquals("\u001b[1;5C", str(TerminalKey.Right, KeyModifiers(ctrl = true), app = true))
        assertEquals("\u001b[1;2A", str(TerminalKey.Up, KeyModifiers(shift = true)))
    }

    @Test
    fun homeEnd() {
        assertEquals("\u001b[H", str(TerminalKey.Home))
        assertEquals("\u001b[F", str(TerminalKey.End))
        assertEquals("\u001bOH", str(TerminalKey.Home, app = true))
    }

    @Test
    fun functionAndEditingKeys() {
        assertEquals("\u001bOP", str(TerminalKey.F1))
        assertEquals("\u001b[1;2P", str(TerminalKey.F1, KeyModifiers(shift = true)))
        assertEquals("\u001b[15~", str(TerminalKey.F5))
        assertEquals("\u001b[24~", str(TerminalKey.F12))
        assertEquals("\u001b[3~", str(TerminalKey.Delete))
        assertEquals("\u001b[5~", str(TerminalKey.PageUp))
        assertEquals("\u001b[6~", str(TerminalKey.PageDown))
        assertEquals("\u001b[2~", str(TerminalKey.Insert))
    }

    @Test
    fun simpleKeys() {
        assertEquals("\r", str(TerminalKey.Enter))
        assertEquals("\u007f", str(TerminalKey.Backspace))
        assertEquals("\t", str(TerminalKey.Tab))
        assertEquals("\u001b[Z", str(TerminalKey.Tab, KeyModifiers(shift = true)))
        assertEquals("\u001b", str(TerminalKey.Escape))
    }

    @Test
    fun ctrlLetterIsControlCode() {
        assertContentEquals(byteArrayOf(0x03), XtermKeyEncoder.encodeCodePoint('c'.code, KeyModifiers(ctrl = true)))
        assertContentEquals(byteArrayOf(0x04), XtermKeyEncoder.encodeCodePoint('D'.code, KeyModifiers(ctrl = true)))
    }

    @Test
    fun altPrefixesEscape() {
        assertContentEquals(byteArrayOf(0x1b, 'x'.code.toByte()), XtermKeyEncoder.encodeCodePoint('x'.code, KeyModifiers(alt = true)))
    }

    @Test
    fun printableIsUtf8() {
        assertContentEquals("a".encodeToByteArray(), XtermKeyEncoder.encodeCodePoint('a'.code))
        assertContentEquals("é".encodeToByteArray(), XtermKeyEncoder.encodeCodePoint(0xE9))
        assertContentEquals("世".encodeToByteArray(), XtermKeyEncoder.encodeCodePoint(0x4E16))
        assertContentEquals("😀".encodeToByteArray(), XtermKeyEncoder.encodeCodePoint(0x1F600))
    }

    @Test
    fun nonTextCodePointsAreRejected() {
        assertNull(XtermKeyEncoder.encodeCodePoint(0))
        assertNull(XtermKeyEncoder.encodeCodePoint(0x7f))
    }
}
