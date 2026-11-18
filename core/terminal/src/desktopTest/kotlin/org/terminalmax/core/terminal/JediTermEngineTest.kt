// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JediTermEngineTest {
    private fun engine(cols: Int = 20, rows: Int = 5) = createTerminalEngine(cols, rows)

    private fun TerminalEngine.feed(s: String) = feed(s.encodeToByteArray())

    @Test
    fun helloLandsOnRowZero() {
        val e = engine()
        e.feed("hello")
        val s = e.snapshot()
        assertEquals("hello", s.rowText(0))
        assertEquals(20, s.lines[0].size)
        assertEquals(5, s.cursorCol)
        assertEquals(0, s.cursorRow)
        assertTrue(e.revision.value > 0)
    }

    @Test
    fun sgrRedForeground() {
        val e = engine()
        e.feed("\u001b[31mred\u001b[0mx")
        val row = e.snapshot().lines[0]
        for (i in 0..2) assertEquals(TerminalColor.Indexed(1), row[i].style.fg, "cell $i")
        assertEquals(TerminalColor.Default, row[3].style.fg)
    }

    @Test
    fun truecolourAndAttributes() {
        val e = engine()
        e.feed("\u001b[1;4;38;2;10;20;30mA\u001b[0m\u001b[38;5;200mB")
        val row = e.snapshot().lines[0]
        assertEquals(TerminalColor.Rgb(10, 20, 30), row[0].style.fg)
        assertTrue(row[0].style.bold)
        assertTrue(row[0].style.underline)
        assertEquals(TerminalColor.Indexed(200), row[1].style.fg)
    }

    @Test
    fun crlfMovesCursor() {
        val e = engine()
        e.feed("ab\r\ncd")
        val s = e.snapshot()
        assertEquals("ab", s.rowText(0))
        assertEquals("cd", s.rowText(1))
        assertEquals(2, s.cursorCol)
        assertEquals(1, s.cursorRow)
    }

    @Test
    fun clearScreenAndCursorPosition() {
        val e = engine()
        e.feed("hello\u001b[2J\u001b[3;5Hx")
        val s = e.snapshot()
        assertEquals("", s.rowText(0))
        assertEquals("x", s.lines[2][4].text)
        assertEquals(5, s.cursorCol)
        assertEquals(2, s.cursorRow)
    }

    @Test
    fun utf8SequenceSplitAcrossFeeds() {
        val e = engine()
        val bytes = "hé世".encodeToByteArray()
        // h, then first byte of e-acute | second byte + first two bytes of CJK | last byte
        e.feed(bytes, 0, 2)
        e.feed(bytes, 2, 3)
        e.feed(bytes, 5, bytes.size - 5)
        assertEquals("hé世", e.snapshot().rowText(0))
    }

    @Test
    fun escapeSequenceSplitAcrossFeeds() {
        val e = engine()
        e.feed("\u001b[3")
        e.feed("1mq")
        assertEquals(TerminalColor.Indexed(1), e.snapshot().lines[0][0].style.fg)
        assertEquals("q", e.snapshot().rowText(0))
    }

    @Test
    fun wideCharacterTakesTwoColumns() {
        val e = engine()
        e.feed("a世b")
        val row = e.snapshot().lines[0]
        assertEquals("a", row[0].text)
        assertEquals(2, row[1].width)
        assertEquals("世", row[1].text)
        assertEquals(0, row[2].width)
        assertEquals("b", row[3].text)
        assertEquals(4, e.snapshot().cursorCol)
    }

    @Test
    fun resizeKeepsContent() {
        val e = engine(20, 5)
        e.feed("hello")
        e.resize(40, 10)
        val s = e.snapshot()
        assertEquals(40, e.cols)
        assertEquals(10, e.rows)
        assertEquals(40, s.cols)
        assertEquals(10, s.lines.size)
        assertEquals("hello", s.rowText(0))
    }

    @Test
    fun alternateScreenRestoresMainScreen() {
        val e = engine()
        e.feed("main")
        e.feed("\u001b[?1049h\u001b[2J\u001b[Halt")
        assertEquals("alt", e.snapshot().rowText(0))
        assertTrue(e.snapshot().alternateScreen)
        e.feed("\u001b[?1049l")
        assertEquals("main", e.snapshot().rowText(0))
        assertEquals(false, e.snapshot().alternateScreen)
    }

    @Test
    fun deviceStatusReportIsAnsweredThroughOnResponse() {
        val e = engine()
        val responses = mutableListOf<String>()
        e.onResponse = { responses += it.decodeToString() }
        e.feed("ab\u001b[6n")
        assertEquals(listOf("\u001b[1;3R"), responses)
    }

    @Test
    fun scrollbackGrowsPastScreenHeight() {
        val e = engine(20, 5)
        for (i in 1..12) e.feed("line $i\r\n")
        val s = e.snapshot()
        assertTrue(s.scrollbackSize >= 7, "scrollback was ${s.scrollbackSize}")
        assertEquals("line 12", s.rowText(3))
    }

    @Test
    fun titleAndCursorVisibility() {
        val e = engine()
        e.feed("\u001b]0;my title\u0007")
        assertEquals("my title", e.snapshot().title)
        e.feed("\u001b[?25l")
        assertEquals(false, e.snapshot().cursorVisible)
        e.feed("\u001b[?25h")
        assertEquals(true, e.snapshot().cursorVisible)
    }

    @Test
    fun applicationCursorModeChangesArrowEncoding() {
        val e = engine()
        assertEquals("\u001b[A", e.encodeKey(TerminalKey.Up).decodeToString())
        e.feed("\u001b[?1h")
        assertEquals("\u001bOA", e.encodeKey(TerminalKey.Up).decodeToString())
        e.feed("\u001b[?1l")
        assertEquals("\u001b[A", e.encodeKey(TerminalKey.Up).decodeToString())
    }
}
