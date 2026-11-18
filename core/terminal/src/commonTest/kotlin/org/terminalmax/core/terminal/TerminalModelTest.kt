// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import androidx.compose.ui.graphics.Color
import org.terminalmax.core.terminal.ui.TerminalPalette
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class TerminalModelTest {
    @Test
    fun indexedColorRangeIsChecked() {
        assertFailsWith<IllegalArgumentException> { TerminalColor.Indexed(256) }
    }

    @Test
    fun paletteColourCube() {
        val p = TerminalPalette.Default
        assertEquals(Color(0, 0, 0), p.indexed(16))
        assertEquals(Color(255, 255, 255), p.indexed(231))
        assertEquals(Color(95, 0, 0), p.indexed(52))
        assertEquals(Color(8, 8, 8), p.indexed(232))
        assertEquals(Color(238, 238, 238), p.indexed(255))
        assertEquals(p.ansi[1], p.indexed(1))
    }
}
