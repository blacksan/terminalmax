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
 *
 * Host output is untrusted. Hardening, in the order the data flows:
 * 1. UTF-8 decoding replaces malformed input and carries at most 3 bytes between calls.
 * 2. [EscapeSequenceFilter] bounds pending escape sequences and clamps CSI parameters.
 * 3. The emulator runs with remote resize requests ignored ([TrackingTerminal]).
 * 4. Responses are collected under the lock and delivered after it is released.
 */
internal class JediTermEngine(
    cols: Int,
    rows: Int,
    scrollbackLines: Int,
) : TerminalEngine {
    private val lock = Any()
    private val styleState = StyleState()
    private val buffer = TerminalTextBuffer(
        cols.coerceIn(TerminalLimits.MIN_COLS, TerminalLimits.MAX_COLS),
        rows.coerceIn(TerminalLimits.MIN_ROWS, TerminalLimits.MAX_ROWS),
        styleState,
        scrollbackLines,
    )
    private val display = HeadlessDisplay()
    private val terminal = TrackingTerminal(display, buffer, styleState)
    private val filter = EscapeSequenceFilter()
    private val stream = SequenceStream()
    private val emulator = JediEmulator(stream, terminal)
    private val decoder = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPLACE)
        .onUnmappableCharacter(CodingErrorAction.REPLACE)
    private var pendingBytes = ByteArray(0)
    private var closed = false
    private val styleCache = HashMap<TextStyle, CellStyle>()
    private val _revision = MutableStateFlow(0L)

    // Responses produced while the lock is held; delivered to onResponse after it is released.
    private val pendingResponses = ArrayList<ByteArray>() // guarded by lock
    private var pendingResponseBytes = 0 // guarded by lock

    /** Characters held back for unfinished escape sequences (filter plus emulator retry buffer). Test hook. */
    internal val pendingChars: Int
        get() = synchronized(lock) { filter.pendingLength + stream.pendingLength() }

    @Volatile
    override var onResponse: ((ByteArray) -> Unit)? = null

    override val revision: StateFlow<Long> = _revision.asStateFlow()

    override val cols: Int get() = synchronized(lock) { terminal.getTerminalWidth() }
    override val rows: Int get() = synchronized(lock) { terminal.getTerminalHeight() }

    init {
        terminal.setTerminalOutput(object : TerminalOutputStream {
            override fun sendBytes(response: ByteArray, userInput: Boolean) {
                queueResponse(response)
            }

            override fun sendString(string: String, userInput: Boolean) {
                queueResponse(string.encodeToByteArray())
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
            val safe = StringBuilder(chars.size)
            filter.filter(chars, chars.size, safe)
            stream.append(safe.toString().toCharArray())

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
                    // End of data in the middle of an escape sequence: wait for the rest. The filter
                    // only forwards complete sequences, so this is a safety net; it is bounded too.
                    emulator.resetEof()
                    if (stream.trailLength() > MAX_PENDING_CHARS) stream.dropTrail() else stream.restoreTrail()
                    break
                }
            }
        }
        _revision.update { it + 1 }
        deliverResponses()
    }

    private fun queueResponse(bytes: ByteArray) {
        synchronized(lock) {
            if (pendingResponseBytes + bytes.size > MAX_RESPONSE_BYTES) return // flood: drop
            pendingResponseBytes += bytes.size
            pendingResponses.add(bytes)
        }
    }

    /** Calls [onResponse] for collected responses. Never called with [lock] held. */
    private fun deliverResponses() {
        val batch: List<ByteArray> = synchronized(lock) {
            if (pendingResponses.isEmpty()) {
                emptyList()
            } else {
                ArrayList(pendingResponses).also {
                    pendingResponses.clear()
                    pendingResponseBytes = 0
                }
            }
        }
        if (batch.isEmpty()) return
        val callback = onResponse ?: return
        for (response in batch) callback(response)
    }

    override fun resize(cols: Int, rows: Int) {
        synchronized(lock) {
            if (closed) return
            terminal.resize(
                TermSize(
                    cols.coerceIn(TerminalLimits.MIN_COLS, TerminalLimits.MAX_COLS),
                    rows.coerceIn(TerminalLimits.MIN_ROWS, TerminalLimits.MAX_ROWS),
                ),
                RequestOrigin.User,
            )
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
            pendingResponses.clear()
            pendingResponseBytes = 0
            filter.reset()
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
                    // A stray width marker still occupies a column.
                    cells.add(Cell("", style, 0))
                    i++
                    continue
                }
                // JediTerm keeps a surrogate pair as two columns, and a double-width character is
                // followed by one DWC marker column. Emit exactly as many cells as columns it
                // reserved (a width-2 cell followed by width-0 placeholders) so every later cell
                // stays aligned with the emulator's cursor.
                val isPair = ch.isHighSurrogate() && i + 1 < n && text[i + 1].isLowSurrogate()
                val unit = if (isPair) 2 else 1
                val str = when {
                    isPair -> text.substring(i, i + 2)
                    ch == '\u0000' -> " "
                    else -> ch.toString()
                }
                val hasMarker = i + unit < n && text[i + unit] == DWC
                val columns = unit + if (hasMarker) 1 else 0
                cells.add(Cell(str, style, if (isPair || hasMarker) 2 else 1))
                for (k in 1 until columns) {
                    if (cells.size < width) cells.add(Cell("", style, 0))
                }
                i += columns
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
        /** Upper bound for characters held back for an unfinished escape sequence. */
        const val MAX_PENDING_CHARS = EscapeSequenceFilter.MAX_PENDING

        /** Responses queued per feed/resize call beyond this are dropped (DSR flood). */
        const val MAX_RESPONSE_BYTES = 64 * 1024

        /** JediTerm marks the second half of a double-width character with this private-use char. */
        const val DWC = '\uE000'
    }
}

/**
 * JediTerminal that remembers DECCKM (application cursor keys) for our own key encoder and
 * hardens the parts the host can reach: remote resizes are ignored, local ones clamped, and the
 * window-title stack is bounded.
 *
 * Verified against JediTerm sources: `JediTerminal` and `resize`, `saveWindowTitleOnStack`,
 * `restoreWindowTitleFromStack`, `setApplicationArrowKeys` are public and non-final; the only caller
 * of a resize from output is `CSI 8 ; rows ; cols t` with `RequestOrigin.Remote`.
 */
private class TrackingTerminal(
    display: TerminalDisplay,
    buf: TerminalTextBuffer,
    styleState: StyleState,
) : JediTerminal(display, buf, styleState) {
    @Volatile
    var appCursorKeysEnabled: Boolean = false

    private var titleStackDepth = 0

    override fun resize(newTermSize: TermSize, origin: RequestOrigin) {
        // The host must never change the size (xterm: allowWindowOps off). Local sizes are clamped.
        if (origin == RequestOrigin.Remote) return
        super.resize(
            TermSize(
                newTermSize.getColumns().coerceIn(TerminalLimits.MIN_COLS, TerminalLimits.MAX_COLS),
                newTermSize.getRows().coerceIn(TerminalLimits.MIN_ROWS, TerminalLimits.MAX_ROWS),
            ),
            origin,
        )
    }

    // `CSI 22 t` pushes onto an unbounded stack inside JediTerm; keep our own depth and refuse the
    // push beyond MAX_TITLE_STACK, so pops stay paired with pushes that really happened.
    override fun saveWindowTitleOnStack() {
        if (titleStackDepth >= MAX_TITLE_STACK) return
        titleStackDepth++
        super.saveWindowTitleOnStack()
    }

    override fun restoreWindowTitleFromStack() {
        if (titleStackDepth == 0) return
        titleStackDepth--
        super.restoreWindowTitleFromStack()
    }

    private companion object {
        const val MAX_TITLE_STACK = 10
    }

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
        // Titles are attacker-controlled: strip controls/bidi overrides and cap the length.
        titleText = TitleSanitizer.sanitize(windowTitle)
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

    /** Characters not yet consumed by the emulator. */
    fun pendingLength(): Int = myLength

    fun trailLength(): Int = trail.length

    fun dropTrail() {
        trail.setLength(0)
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
