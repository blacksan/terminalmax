// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import com.jediterm.core.util.TermSize
import com.jediterm.terminal.ArrayTerminalDataStream
import com.jediterm.terminal.CursorShape
import com.jediterm.terminal.RequestOrigin
import com.jediterm.terminal.TerminalDisplay
import com.jediterm.terminal.TerminalOutputStream
import com.jediterm.terminal.TextStyle
import com.jediterm.terminal.emulator.JediEmulator
import com.jediterm.terminal.emulator.mouse.MouseFormat
import com.jediterm.terminal.emulator.mouse.MouseMode
import com.jediterm.terminal.model.JediTerminal
import com.jediterm.terminal.model.StyleState
import com.jediterm.terminal.model.TerminalLine
import com.jediterm.terminal.model.TerminalSelection
import com.jediterm.terminal.model.TerminalTextBuffer
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.CharBuffer
import java.nio.charset.CodingErrorAction
import com.jediterm.terminal.TerminalColor as JediColor

/**
 * [TerminalEngine] backed by JediTerm's AWT-free `jediterm-core` emulator. Shared verbatim by the
 * Android and desktop targets.
 */
internal class JediTermEngine(
    cols: Int,
    rows: Int,
    scrollbackLines: Int,
) : TerminalEngine {
    private val lock = Any()
    private val styleState = StyleState()
    private val buffer = TerminalTextBuffer(cols, rows, styleState, scrollbackLines)
    private val display = HeadlessDisplay()
    private val terminal = TrackingTerminal(display, buffer, styleState)
    private val stream = SequenceStream()
    private val emulator = JediEmulator(stream, terminal)
    private val decoder = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    private var pendingBytes = ByteArray(0)
    private var closed = false
    private val styleCache = HashMap<TextStyle, CellStyle>()
    private val _revision = MutableStateFlow(0L)

    @Volatile
    override var onResponse: ((ByteArray) -> Unit)? = null

    override val revision: StateFlow<Long> = _revision.asStateFlow()

    override val cols: Int get() = synchronized(lock) { terminal.getTerminalWidth() }
    override val rows: Int get() = synchronized(lock) { terminal.getTerminalHeight() }

    init {
        terminal.setTerminalOutput(object : TerminalOutputStream {
            override fun sendBytes(response: ByteArray, userInput: Boolean) {
                onResponse?.invoke(response)
            }

            override fun sendString(string: String, userInput: Boolean) {
                onResponse?.invoke(string.encodeToByteArray())
            }
        })
    }

    override fun feed(bytes: ByteArray, offset: Int, length: Int) {
        require(offset >= 0 && length >= 0 && offset + length <= bytes.size) { "Bad range" }
        if (length == 0) return
        synchronized(lock) {
            if (closed) return
            // Carry an incomplete trailing UTF-8 sequence over to the next call.
            val data = ByteArray(pendingBytes.size + length)
            pendingBytes.copyInto(data, 0, 0, pendingBytes.size)
            bytes.copyInto(data, pendingBytes.size, offset, offset + length)
            val input = ByteBuffer.wrap(data)
            val out = CharBuffer.allocate(data.size + 2)
            decoder.reset()
            decoder.decode(input, out, false)
            pendingBytes = ByteArray(input.remaining()).also { input.get(it) }
            out.flip()
            val chars = CharArray(out.remaining())
            out.get(chars)
            stream.append(chars)

            while (!stream.isEmpty()) {
                stream.begin()
                try {
                    emulator.next()
                } catch (e: IOException) {
                    // Treated like a malformed sequence: continue with the next character.
                } catch (e: RuntimeException) {
                    // A emulator bug must not kill the session; drop the offending character.
                }
                if (!emulator.hasNext()) {
                    // End of data in the middle of an escape sequence: wait for the rest.
                    emulator.resetEof()
                    stream.restoreTrail()
                    break
                }
            }
        }
        _revision.update { it + 1 }
    }

    override fun resize(cols: Int, rows: Int) {
        synchronized(lock) {
            if (closed) return
            terminal.resize(TermSize(cols.coerceAtLeast(2), rows.coerceAtLeast(2)), RequestOrigin.User)
        }
        _revision.update { it + 1 }
    }

    override fun snapshot(): TerminalSnapshot = synchronized(lock) {
        val w = terminal.getTerminalWidth()
        val h = terminal.getTerminalHeight()
        buffer.lock()
        try {
            val lines = List(h) { r -> lineToCells(buffer.getLine(r), w) }
            TerminalSnapshot(
                cols = w,
                rows = h,
                lines = lines,
                // JediTerm cursor coordinates are 1-based.
                cursorCol = (terminal.getCursorX() - 1).coerceIn(0, w - 1),
                cursorRow = (terminal.getCursorY() - 1).coerceIn(0, h - 1),
                cursorVisible = display.cursorShown,
                title = display.titleText.ifEmpty { null },
                scrollbackSize = buffer.historyLinesCount,
                alternateScreen = display.onAlternateScreen,
            )
        } finally {
            buffer.unlock()
        }
    }

    override fun encodeKey(key: TerminalKey, modifiers: KeyModifiers): ByteArray =
        XtermKeyEncoder.encode(key, modifiers, terminal.appCursorKeysEnabled)

    override fun close() {
        synchronized(lock) {
            closed = true
            terminal.setTerminalOutput(null)
        }
    }

    private fun lineToCells(line: TerminalLine, width: Int): List<Cell> {
        val cells = ArrayList<Cell>(width)
        for (entry in line.getEntries()) {
            val style = mapStyle(entry.getStyle())
            val text = entry.getText()
            val n = text.length
            if (entry.isNul()) {
                // Never-written cells (may still carry an erase background colour).
                for (i in 0 until n) {
                    if (cells.size >= width) break
                    cells.add(Cell(" ", style, 1))
                }
                continue
            }
            var i = 0
            while (i < n && cells.size < width) {
                val ch = text[i]
                if (ch == DWC) {
                    i++
                    continue
                }
                var consumed = 1
                val str = if (ch.isHighSurrogate() && i + 1 < n && text[i + 1].isLowSurrogate()) {
                    consumed = 2
                    charArrayOf(ch, text[i + 1]).concatToString()
                } else if (ch == '\u0000') {
                    " "
                } else {
                    ch.toString()
                }
                val wide = i + consumed < n && text[i + consumed] == DWC
                if (wide) {
                    cells.add(Cell(str, style, 2))
                    if (cells.size < width) cells.add(Cell("", style, 0))
                    consumed += 1
                } else {
                    cells.add(Cell(str, style, 1))
                }
                i += consumed
            }
        }
        while (cells.size < width) cells.add(Cell.Blank)
        return if (cells.size > width) cells.subList(0, width).toList() else cells
    }

    private fun mapStyle(s: TextStyle): CellStyle {
        styleCache[s]?.let { return it }
        val mapped = CellStyle(
            fg = mapColor(s.getForeground()),
            bg = mapColor(s.getBackground()),
            bold = s.hasOption(TextStyle.Option.BOLD),
            italic = s.hasOption(TextStyle.Option.ITALIC),
            underline = s.hasOption(TextStyle.Option.UNDERLINED),
            inverse = s.hasOption(TextStyle.Option.INVERSE),
            dim = s.hasOption(TextStyle.Option.DIM),
            strikethrough = false, // JediTerm has no strikethrough attribute.
        )
        if (styleCache.size > 512) styleCache.clear()
        styleCache[s] = mapped
        return mapped
    }

    private fun mapColor(c: JediColor?): TerminalColor = when {
        c == null -> TerminalColor.Default
        c.isIndexed() -> TerminalColor.Indexed(c.getColorIndex().coerceIn(0, 255))
        else -> {
            val rgb = c.toColor()
            TerminalColor.Rgb(rgb.getRed(), rgb.getGreen(), rgb.getBlue())
        }
    }

    private companion object {
        /** JediTerm marks the second half of a double-width character with this private-use char. */
        const val DWC = ''
    }
}

/** JediTerminal that remembers DECCKM (application cursor keys) for our own key encoder. */
private class TrackingTerminal(
    display: TerminalDisplay,
    buf: TerminalTextBuffer,
    styleState: StyleState,
) : JediTerminal(display, buf, styleState) {
    @Volatile
    var appCursorKeysEnabled: Boolean = false

    override fun setApplicationArrowKeys(enabled: Boolean) {
        appCursorKeysEnabled = enabled
        super.setApplicationArrowKeys(enabled)
    }
}

/** Minimal headless display: records state the snapshot needs, ignores the rest. */
private class HeadlessDisplay : TerminalDisplay {
    @Volatile var cursorShown: Boolean = true
    @Volatile var onAlternateScreen: Boolean = false
    @Volatile var titleText: String = ""

    override fun setCursor(x: Int, y: Int) {}
    override fun setCursorShape(cursorShape: CursorShape?) {}
    override fun beep() {}
    override fun scrollArea(scrollRegionTop: Int, scrollRegionSize: Int, dy: Int) {}
    override fun setCursorVisible(isCursorVisible: Boolean) {
        cursorShown = isCursorVisible
    }

    override fun useAlternateScreenBuffer(useAlternateScreenBuffer: Boolean) {
        onAlternateScreen = useAlternateScreenBuffer
    }

    override fun getWindowTitle(): String = titleText
    override fun setWindowTitle(windowTitle: String) {
        titleText = windowTitle
    }

    override fun getSelection(): TerminalSelection? = null
    override fun terminalMouseModeSet(mouseMode: MouseMode) {}
    override fun setMouseFormat(mouseFormat: MouseFormat) {}
    override fun ambiguousCharsAreDoubleWidth(): Boolean = false
}

/**
 * Char source for [JediEmulator]. Records the characters consumed by the current `next()` call so
 * that a sequence cut off by the end of the available data can be pushed back and retried when
 * more bytes arrive.
 */
private class SequenceStream : ArrayTerminalDataStream(CharArray(0)) {
    private val trail = StringBuilder()

    fun begin() {
        trail.setLength(0)
    }

    fun append(chars: CharArray) {
        if (chars.isEmpty()) return
        val merged = CharArray(myLength + chars.size)
        System.arraycopy(myBuf, myOffset, merged, 0, myLength)
        System.arraycopy(chars, 0, merged, myLength, chars.size)
        myBuf = merged
        myOffset = 0
        myLength = merged.size
    }

    fun restoreTrail() {
        if (trail.isEmpty()) return
        val chars = trail.toString().toCharArray()
        trail.setLength(0)
        super.pushBackBuffer(chars, chars.size)
    }

    override fun getChar(): Char {
        val c = super.getChar()
        trail.append(c)
        return c
    }

    override fun pushChar(c: Char) {
        super.pushChar(c)
        if (trail.isNotEmpty()) trail.setLength(trail.length - 1)
    }

    override fun readNonControlCharacters(maxChars: Int): String {
        val s = super.readNonControlCharacters(maxChars)
        trail.append(s)
        return s
    }

    override fun pushBackBuffer(chars: CharArray, length: Int) {
        super.pushBackBuffer(chars, length)
        trail.setLength(maxOf(0, trail.length - length))
    }
}
