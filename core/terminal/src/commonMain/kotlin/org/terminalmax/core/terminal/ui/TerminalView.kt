// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.focusable
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isAltPressed
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isMetaPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.input.key.utf16CodePoint
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.text.TextMeasurer
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.drawText
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.IntSize
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.sp
import org.terminalmax.core.terminal.Cell
import org.terminalmax.core.terminal.CellStyle
import org.terminalmax.core.terminal.KeyModifiers
import org.terminalmax.core.terminal.TerminalColor
import org.terminalmax.core.terminal.TerminalEngine
import org.terminalmax.core.terminal.TerminalKey
import org.terminalmax.core.terminal.XtermKeyEncoder

/** Colours and flags of one [CellStyle] after palette lookup, inverse and dim handling. */
private class ResolvedStyle(
    val fg: Color,
    val bg: Color,
    val bold: Boolean,
    val italic: Boolean,
    val underline: Boolean,
    val strikethrough: Boolean,
) {
    fun sameGlyphStyle(o: ResolvedStyle) =
        fg == o.fg && bold == o.bold && italic == o.italic && underline == o.underline &&
            strikethrough == o.strikethrough
}

private const val MEASURE_REPEAT = 32

/**
 * Shared Compose Canvas renderer for a [TerminalEngine].
 *
 * Hardware keyboard only: soft-keyboard/IME input on Android is out of scope for this spike.
 */
@Composable
fun TerminalView(
    engine: TerminalEngine,
    modifier: Modifier = Modifier,
    fontSize: TextUnit = 14.sp,
    palette: TerminalPalette = TerminalPalette.Default,
    onInput: (ByteArray) -> Unit,
    onSizeChanged: (cols: Int, rows: Int) -> Unit = { _, _ -> },
) {
    val textMeasurer = rememberTextMeasurer(cacheSize = 512)
    val baseStyle = remember(fontSize, palette) {
        TextStyle(fontFamily = FontFamily.Monospace, fontSize = fontSize, color = palette.foreground)
    }
    val cellSize = remember(textMeasurer, baseStyle) {
        val layout = textMeasurer.measure(
            text = "M".repeat(MEASURE_REPEAT),
            style = baseStyle,
            softWrap = false,
            maxLines = 1,
        )
        Size(layout.size.width.toFloat() / MEASURE_REPEAT, layout.size.height.toFloat())
    }
    val cellW = cellSize.width
    val cellH = cellSize.height

    var pixelSize by remember { mutableStateOf(IntSize.Zero) }
    var focused by remember { mutableStateOf(false) }
    val focusRequester = remember { FocusRequester() }
    val currentOnInput by rememberUpdatedState(onInput)
    val currentOnSizeChanged by rememberUpdatedState(onSizeChanged)

    LaunchedEffect(engine, pixelSize, cellW, cellH) {
        if (pixelSize.width > 0 && pixelSize.height > 0 && cellW > 0f && cellH > 0f) {
            val newCols = (pixelSize.width / cellW).toInt().coerceAtLeast(2)
            val newRows = (pixelSize.height / cellH).toInt().coerceAtLeast(2)
            if (newCols != engine.cols || newRows != engine.rows) {
                engine.resize(newCols, newRows)
            }
            currentOnSizeChanged(newCols, newRows)
        }
    }

    // Re-read the snapshot whenever the engine reports a change.
    val revision by engine.revision.collectAsState()
    val snapshot = remember(engine, revision) { engine.snapshot() }

    val resolvedCache = remember(palette) { HashMap<CellStyle, ResolvedStyle>() }

    Canvas(
        modifier = modifier
            .clipToBounds()
            .onSizeChanged { pixelSize = it }
            .focusRequester(focusRequester)
            .onFocusChanged { focused = it.isFocused }
            .onPreviewKeyEvent { event -> handleKeyEvent(event, engine) { currentOnInput(it) } }
            .focusable()
            .pointerInput(Unit) { detectTapGestures { focusRequester.requestFocus() } },
    ) {
        drawRect(palette.background)
        val rowsToDraw = minOf(snapshot.rows, snapshot.lines.size)
        for (r in 0 until rowsToDraw) {
            val row = snapshot.lines[r]
            val y = r * cellH
            val resolved = row.map { resolve(it.style, palette, resolvedCache) }

            // Backgrounds: one rect per run of equal colour.
            var c = 0
            while (c < row.size) {
                val bg = resolved[c].bg
                var e = c + 1
                while (e < row.size && resolved[e].bg == bg) e++
                if (bg != palette.background) {
                    drawRect(bg, Offset(c * cellW, y), Size((e - c) * cellW, cellH))
                }
                c = e
            }

            // Text: ASCII runs of equal style are drawn as one string; everything else per cell so
            // glyphs with a different advance (box drawing, CJK) stay on the grid.
            c = 0
            while (c < row.size) {
                val cell = row[c]
                if (cell.width == 0) {
                    c++
                    continue
                }
                val rs = resolved[c]
                if (!isPlainAscii(cell)) {
                    if (cell.text.isNotBlank()) {
                        drawRun(textMeasurer, baseStyle, cell.text, rs, Offset(c * cellW, y))
                    }
                    c++
                    continue
                }
                var e = c + 1
                val sb = StringBuilder(cell.text)
                while (e < row.size && isPlainAscii(row[e]) && resolved[e].sameGlyphStyle(rs)) {
                    sb.append(row[e].text)
                    e++
                }
                val text = sb.toString()
                if (text.isNotBlank() || rs.underline || rs.strikethrough) {
                    drawRun(textMeasurer, baseStyle, text, rs, Offset(c * cellW, y))
                }
                c = e
            }
        }

        if (snapshot.cursorVisible) {
            val topLeft = Offset(snapshot.cursorCol * cellW, snapshot.cursorRow * cellH)
            val size = Size(cellW, cellH)
            if (focused) {
                drawRect(palette.cursor.copy(alpha = 0.7f), topLeft, size)
            } else {
                drawRect(palette.cursor, topLeft, size, style = Stroke(width = 1f))
            }
        }
    }
}

private fun isPlainAscii(cell: Cell): Boolean =
    cell.width == 1 && cell.text.length == 1 && cell.text[0].code in 0x20..0x7e

private fun androidx.compose.ui.graphics.drawscope.DrawScope.drawRun(
    measurer: TextMeasurer,
    base: TextStyle,
    text: String,
    rs: ResolvedStyle,
    topLeft: Offset,
) {
    val decoration = when {
        rs.underline && rs.strikethrough ->
            TextDecoration.combine(listOf(TextDecoration.Underline, TextDecoration.LineThrough))
        rs.underline -> TextDecoration.Underline
        rs.strikethrough -> TextDecoration.LineThrough
        else -> null
    }
    val style = base.copy(
        color = rs.fg,
        fontWeight = if (rs.bold) FontWeight.Bold else null,
        fontStyle = if (rs.italic) FontStyle.Italic else null,
        textDecoration = decoration,
    )
    drawText(
        textMeasurer = measurer,
        text = text,
        topLeft = topLeft,
        style = style,
        softWrap = false,
        maxLines = 1,
    )
}

private fun resolveColor(color: TerminalColor, default: Color, palette: TerminalPalette, brighten: Boolean): Color =
    when (color) {
        TerminalColor.Default -> default
        is TerminalColor.Indexed ->
            palette.indexed(if (brighten && color.index in 0..7) color.index + 8 else color.index)
        is TerminalColor.Rgb -> Color(color.r, color.g, color.b)
    }

private fun resolve(style: CellStyle, palette: TerminalPalette, cache: HashMap<CellStyle, ResolvedStyle>): ResolvedStyle =
    cache.getOrPut(style) {
        var fg = resolveColor(style.fg, palette.foreground, palette, brighten = style.bold)
        var bg = resolveColor(style.bg, palette.background, palette, brighten = false)
        if (style.inverse) {
            val t = fg
            fg = bg
            bg = t
        }
        if (style.dim) fg = fg.copy(alpha = fg.alpha * 0.6f)
        ResolvedStyle(fg, bg, style.bold, style.italic, style.underline, style.strikethrough)
    }

private fun mapSpecialKey(key: Key): TerminalKey? = when (key) {
    Key.Enter, Key.NumPadEnter -> TerminalKey.Enter
    Key.Backspace -> TerminalKey.Backspace
    Key.Tab -> TerminalKey.Tab
    Key.Escape -> TerminalKey.Escape
    Key.DirectionUp -> TerminalKey.Up
    Key.DirectionDown -> TerminalKey.Down
    Key.DirectionLeft -> TerminalKey.Left
    Key.DirectionRight -> TerminalKey.Right
    Key.MoveHome -> TerminalKey.Home
    Key.MoveEnd -> TerminalKey.End
    Key.PageUp -> TerminalKey.PageUp
    Key.PageDown -> TerminalKey.PageDown
    Key.Insert -> TerminalKey.Insert
    Key.Delete -> TerminalKey.Delete
    Key.F1 -> TerminalKey.F1
    Key.F2 -> TerminalKey.F2
    Key.F3 -> TerminalKey.F3
    Key.F4 -> TerminalKey.F4
    Key.F5 -> TerminalKey.F5
    Key.F6 -> TerminalKey.F6
    Key.F7 -> TerminalKey.F7
    Key.F8 -> TerminalKey.F8
    Key.F9 -> TerminalKey.F9
    Key.F10 -> TerminalKey.F10
    Key.F11 -> TerminalKey.F11
    Key.F12 -> TerminalKey.F12
    else -> null
}

private fun handleKeyEvent(event: KeyEvent, engine: TerminalEngine, send: (ByteArray) -> Unit): Boolean {
    if (event.type == KeyEventType.KeyUp) {
        // Swallow Escape release too so navigation handlers never see a lone KeyUp.
        return event.key == Key.Escape
    }
    if (event.type != KeyEventType.KeyDown) return false
    val mods = KeyModifiers(ctrl = event.isCtrlPressed, alt = event.isAltPressed, shift = event.isShiftPressed)
    val special = mapSpecialKey(event.key)
    if (special != null) {
        send(engine.encodeKey(special, mods))
        return true
    }
    if (event.isMetaPressed) return false
    val bytes = XtermKeyEncoder.encodeCodePoint(event.utf16CodePoint, mods) ?: return false
    send(bytes)
    return true
}
