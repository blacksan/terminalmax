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
import androidx.compose.ui.text.TextLayoutResult
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
import org.terminalmax.core.terminal.KeyboardInput
import org.terminalmax.core.terminal.TerminalColor
import org.terminalmax.core.terminal.TerminalEngine
import org.terminalmax.core.terminal.TerminalKey
import org.terminalmax.core.terminal.TerminalLimits
import org.terminalmax.core.terminal.TypedTextState
import org.terminalmax.core.terminal.createTypedTextState
import org.terminalmax.core.terminal.isAltGraph
import org.terminalmax.core.terminal.typedText

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

/** Longest ASCII run drawn as one text layout; bounds drift if the font advance is fractional. */
private const val MAX_RUN_COLUMNS = 32

/** The style cache is cleared above this many entries (truecolour streams create endless styles). */
private const val MAX_STYLE_CACHE = 1024

private class BackgroundRun(val startCol: Int, val endCol: Int, val color: Color)

private class TextRun(val col: Int, val layout: TextLayoutResult)

/** Everything needed to draw one row; rebuilt only when the row's cells change. */
private class RowRender(val cells: List<Cell>, val backgrounds: List<BackgroundRun>, val texts: List<TextRun>)

/**
 * Per-view render state: resolved-style cache (bounded) and one cached [RowRender] per screen row.
 * Recreated when the palette, font or measurer changes. Only touched from the draw phase.
 */
private class RenderCache(
    val measurer: TextMeasurer,
    val base: TextStyle,
    val palette: TerminalPalette,
) {
    private val styles = HashMap<CellStyle, ResolvedStyle>()
    private var rows = arrayOfNulls<RowRender>(0)

    fun resolve(style: CellStyle): ResolvedStyle {
        styles[style]?.let { return it }
        if (styles.size >= MAX_STYLE_CACHE) styles.clear()
        val resolved = resolveStyle(style, palette)
        styles[style] = resolved
        return resolved
    }

    fun row(index: Int, cells: List<Cell>, rowCount: Int): RowRender {
        if (rows.size != rowCount) rows = arrayOfNulls(rowCount)
        val cached = rows[index]
        if (cached != null && cached.cells == cells) return cached
        val built = build(cells)
        rows[index] = built
        return built
    }

    private fun build(cells: List<Cell>): RowRender {
        val resolved = ArrayList<ResolvedStyle>(cells.size)
        for (cell in cells) resolved.add(resolve(cell.style))

        // Backgrounds: one rect per run of equal colour.
        val backgrounds = ArrayList<BackgroundRun>()
        var c = 0
        while (c < cells.size) {
            val bg = resolved[c].bg
            var e = c + 1
            while (e < cells.size && resolved[e].bg == bg) e++
            if (bg != palette.background) backgrounds.add(BackgroundRun(c, e, bg))
            c = e
        }

        // Text: ASCII runs of equal style are one layout; everything else is laid out per cell so
        // glyphs with a different advance (box drawing, CJK, emoji, fallback fonts) stay on the grid.
        val texts = ArrayList<TextRun>()
        c = 0
        while (c < cells.size) {
            val cell = cells[c]
            if (cell.width == 0) {
                c++
                continue
            }
            val rs = resolved[c]
            if (!isPlainAscii(cell)) {
                if (cell.text.isNotBlank()) texts.add(TextRun(c, measureRun(cell.text, rs)))
                c++
                continue
            }
            var e = c + 1
            val sb = StringBuilder(cell.text)
            while (e < cells.size && e - c < MAX_RUN_COLUMNS && isPlainAscii(cells[e]) && resolved[e].sameGlyphStyle(rs)) {
                sb.append(cells[e].text)
                e++
            }
            val text = sb.toString()
            if (text.isNotBlank() || rs.underline || rs.strikethrough) texts.add(TextRun(c, measureRun(text, rs)))
            c = e
        }
        return RowRender(cells, backgrounds, texts)
    }

    fun measureRun(text: String, rs: ResolvedStyle, color: Color = rs.fg): TextLayoutResult {
        val decoration = when {
            rs.underline && rs.strikethrough ->
                TextDecoration.combine(listOf(TextDecoration.Underline, TextDecoration.LineThrough))
            rs.underline -> TextDecoration.Underline
            rs.strikethrough -> TextDecoration.LineThrough
            else -> null
        }
        val style = base.copy(
            color = color,
            fontWeight = if (rs.bold) FontWeight.Bold else null,
            fontStyle = if (rs.italic) FontStyle.Italic else null,
            textDecoration = decoration,
        )
        return measurer.measure(text = text, style = style, softWrap = false, maxLines = 1)
    }
}

/**
 * Shared Compose Canvas renderer for a [TerminalEngine].
 *
 * Input: hardware keyboard only (see `core/terminal/README.md`); soft-keyboard/IME input on
 * Android is out of scope for this spike.
 *
 * Rendering: the engine revision is read inside the Canvas draw scope, so output only redraws
 * (no recomposition). Each row is cached and rebuilt only when its cells change.
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
    val textMeasurer = rememberTextMeasurer(cacheSize = 2048)
    val baseStyle = remember(fontSize, palette) {
        TextStyle(
            fontFamily = FontFamily.Monospace,
            fontSize = fontSize,
            color = palette.foreground,
            // Ligatures would merge cells and break the grid.
            fontFeatureSettings = "liga 0, calt 0",
        )
    }
    val cellSize = remember(textMeasurer, baseStyle) {
        val layout = textMeasurer.measure(
            text = "M".repeat(MEASURE_REPEAT),
            style = baseStyle,
            softWrap = false,
            maxLines = 1,
        )
        // getLineRight is the exact (unrounded) advance of the whole line.
        Size(layout.getLineRight(0) / MEASURE_REPEAT, layout.size.height.toFloat())
    }
    val cellW = cellSize.width
    val cellH = cellSize.height

    var pixelSize by remember { mutableStateOf(IntSize.Zero) }
    var focused by remember { mutableStateOf(false) }
    val focusRequester = remember { FocusRequester() }
    val currentOnInput by rememberUpdatedState(onInput)
    val currentOnSizeChanged by rememberUpdatedState(onSizeChanged)
    val keyState = remember { createTypedTextState() }

    LaunchedEffect(engine, pixelSize, cellW, cellH) {
        if (pixelSize.width > 0 && pixelSize.height > 0 && cellW > 0f && cellH > 0f) {
            val newCols = (pixelSize.width / cellW).toInt().coerceIn(TerminalLimits.MIN_COLS, TerminalLimits.MAX_COLS)
            val newRows = (pixelSize.height / cellH).toInt().coerceIn(TerminalLimits.MIN_ROWS, TerminalLimits.MAX_ROWS)
            if (newCols != engine.cols || newRows != engine.rows) {
                engine.resize(newCols, newRows)
            }
            currentOnSizeChanged(newCols, newRows)
        }
    }

    // Observed inside the draw scope below, not here: output redraws without recomposing.
    val revision = engine.revision.collectAsState()

    val renderCache = remember(textMeasurer, baseStyle, palette) { RenderCache(textMeasurer, baseStyle, palette) }

    Canvas(
        modifier = modifier
            .clipToBounds()
            .onSizeChanged { pixelSize = it }
            .focusRequester(focusRequester)
            .onFocusChanged { focused = it.isFocused }
            .onPreviewKeyEvent { event -> handleKeyEvent(event, engine, keyState) { currentOnInput(it) } }
            .focusable()
            .pointerInput(Unit) { detectTapGestures { focusRequester.requestFocus() } },
    ) {
        @Suppress("UNUSED_VARIABLE")
        val observedRevision = revision.value // read in the draw phase so a new revision redraws
        val snapshot = engine.snapshot()
        drawRect(palette.background)
        val rowsToDraw = minOf(snapshot.rows, snapshot.lines.size)
        for (r in 0 until rowsToDraw) {
            val row = renderCache.row(r, snapshot.lines[r], rowsToDraw)
            val y = r * cellH
            for (bg in row.backgrounds) {
                drawRect(bg.color, Offset(bg.startCol * cellW, y), Size((bg.endCol - bg.startCol) * cellW, cellH))
            }
            for (run in row.texts) {
                drawText(run.layout, topLeft = Offset(run.col * cellW, y))
            }
        }

        if (snapshot.cursorVisible && snapshot.cursorRow < snapshot.lines.size) {
            val cursorCell = snapshot.lines[snapshot.cursorRow].getOrNull(snapshot.cursorCol)
            val topLeft = Offset(snapshot.cursorCol * cellW, snapshot.cursorRow * cellH)
            val cursorWidth = cellW * (cursorCell?.width ?: 1).coerceAtLeast(1)
            val size = Size(cursorWidth, cellH)
            if (focused) {
                // Cursor-coloured cell with the glyph redrawn in the background colour.
                drawRect(palette.cursor, topLeft, size)
                if (cursorCell != null && cursorCell.width > 0 && cursorCell.text.isNotBlank()) {
                    val rs = renderCache.resolve(cursorCell.style)
                    drawText(renderCache.measureRun(cursorCell.text, rs, palette.background), topLeft = topLeft)
                }
            } else {
                drawRect(palette.cursor, topLeft, size, style = Stroke(width = 1f))
            }
        }
    }
}

private fun isPlainAscii(cell: Cell): Boolean =
    cell.width == 1 && cell.text.length == 1 && cell.text[0].code in 0x20..0x7e

private fun resolveColor(color: TerminalColor, default: Color, palette: TerminalPalette, brighten: Boolean): Color =
    when (color) {
        TerminalColor.Default -> default
        is TerminalColor.Indexed ->
            palette.indexed(if (brighten && color.index in 0..7) color.index + 8 else color.index)
        is TerminalColor.Rgb -> Color(color.r, color.g, color.b)
    }

private fun resolveStyle(style: CellStyle, palette: TerminalPalette): ResolvedStyle {
    // Bold-as-bright brightens the foreground colour first; inverse then swaps fg and bg (as xterm).
    var fg = resolveColor(style.fg, palette.foreground, palette, brighten = style.bold)
    var bg = resolveColor(style.bg, palette.background, palette, brighten = false)
    if (style.inverse) {
        val t = fg
        fg = bg
        bg = t
    }
    if (style.dim) fg = fg.copy(alpha = fg.alpha * 0.6f)
    return ResolvedStyle(fg, bg, style.bold, style.italic, style.underline, style.strikethrough)
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

/**
 * Key handling (model documented in [KeyboardInput]): special keys and Ctrl/Alt combinations from
 * the key-down, printable text from typed-character events, Meta/Cmd never sent.
 */
private fun handleKeyEvent(
    event: KeyEvent,
    engine: TerminalEngine,
    keys: TypedTextState,
    send: (ByteArray) -> Unit,
): Boolean {
    if (event.type == KeyEventType.KeyUp) {
        // Swallow Escape release too so navigation handlers never see a lone KeyUp.
        return event.key == Key.Escape
    }
    if (event.isMetaPressed) return false // Cmd/Win combinations belong to the host OS
    // AltGraph is a layout shift, not Alt: its characters are plain text.
    val altGraph = isAltGraph(event)
    val mods = KeyModifiers(
        ctrl = event.isCtrlPressed && !altGraph,
        alt = event.isAltPressed && !altGraph,
        shift = event.isShiftPressed,
    )
    val isKeyDown = event.type == KeyEventType.KeyDown
    if (isKeyDown) {
        val special = mapSpecialKey(event.key)
        if (special != null) {
            send(engine.encodeKey(special, mods))
            return true
        }
    }
    val typed = typedText(event, keys)
    if (typed != null) {
        val bytes = KeyboardInput.encodeText(typed.text, mods, typed.carriesCombinations, keys.optionComposes)
            ?: return false
        send(bytes)
        return true
    }
    if (isKeyDown && !altGraph) {
        val bytes = KeyboardInput.encodeKeyDown(event.utf16CodePoint, mods, keys.optionComposes) ?: return false
        send(bytes)
        return true
    }
    return false
}
