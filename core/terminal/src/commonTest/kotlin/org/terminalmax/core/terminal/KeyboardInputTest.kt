// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class KeyboardInputTest {
    private val none = KeyModifiers.None
    private val ctrl = KeyModifiers(ctrl = true)
    private val alt = KeyModifiers(alt = true)
    private val ctrlAlt = KeyModifiers(ctrl = true, alt = true)

    private fun bytes(vararg b: Int) = ByteArray(b.size) { b[it].toByte() }

    @Test
    fun nonCharactersAreRejected() {
        for (cp in listOf(0xFFFF, 0xFFFE, 0x1FFFF, 0x10FFFE, 0xFDD0, 0xFDEF, -1, 0xD800, 0xDFFF, 0x110000)) {
            assertTrue(KeyboardInput.isNonCharacter(cp), "U+${cp.toString(16)}")
        }
        for (cp in listOf('a'.code, 0xE9, 0x4E16, 0x1F600, 0xFFFD, 0xFDCF)) {
            assertFalse(KeyboardInput.isNonCharacter(cp), "U+${cp.toString(16)}")
        }
    }

    @Test
    fun modifierKeyPressesProduceNoBytes() {
        // AWT reports CHAR_UNDEFINED (0xFFFF) for Shift, Ctrl, Alt, CapsLock and dead keys.
        for (m in listOf(none, ctrl, alt, ctrlAlt, KeyModifiers(shift = true))) {
            assertNull(XtermKeyEncoder.encodeCodePoint(0xFFFF, m))
            assertNull(KeyboardInput.encodeKeyDown(0xFFFF, m, optionComposes = false))
            assertNull(KeyboardInput.encodeText("￿", m, combinationsFromText = false, optionComposes = false))
        }
    }

    @Test
    fun translatedControlCodesAreAccepted() {
        assertContentEquals(bytes(0), KeyboardInput.encodeKeyDown(0, ctrl, false)) // Ctrl+@
        assertContentEquals(bytes(0x1c), KeyboardInput.encodeKeyDown(0x1c, ctrl, false)) // Ctrl+\
        assertContentEquals(bytes(0x1d), KeyboardInput.encodeKeyDown(0x1d, ctrl, false)) // Ctrl+]
        assertContentEquals(bytes(0x1e), KeyboardInput.encodeKeyDown(0x1e, ctrl, false)) // Ctrl+^
        assertContentEquals(bytes(0x1f), KeyboardInput.encodeKeyDown(0x1f, ctrl, false)) // Ctrl+_
        assertContentEquals(bytes(3), KeyboardInput.encodeKeyDown(3, ctrl, false)) // Ctrl+C as AWT sends it
        assertContentEquals(bytes(0x1b, 3), KeyboardInput.encodeKeyDown(3, ctrlAlt, false))
    }

    @Test
    fun ctrlSymbolsFollowXterm() {
        assertContentEquals(bytes(0x7f), XtermKeyEncoder.encodeCodePoint('8'.code, ctrl))
        assertContentEquals(bytes(0), XtermKeyEncoder.encodeCodePoint('`'.code, ctrl))
        assertContentEquals(bytes(0), XtermKeyEncoder.encodeCodePoint(' '.code, ctrl))
        assertContentEquals(bytes(0x1c), XtermKeyEncoder.encodeCodePoint('\\'.code, ctrl))
        assertContentEquals(bytes(0x7f), KeyboardInput.encodeKeyDown('8'.code, ctrl, false))
        assertContentEquals(bytes(0), KeyboardInput.encodeKeyDown('`'.code, ctrl, false))
        // NUL is only sent for Ctrl.
        assertNull(XtermKeyEncoder.encodeCodePoint(0, none))
    }

    @Test
    fun keyDownHandlesOnlyCtrlAltCombinationsOfTheBaseSet() {
        assertContentEquals(bytes(3), KeyboardInput.encodeKeyDown('c'.code, ctrl, false))
        assertContentEquals(bytes(0x1b, 'b'.code), KeyboardInput.encodeKeyDown('b'.code, alt, false))
        assertContentEquals(bytes(0x1b, '1'.code), KeyboardInput.encodeKeyDown('1'.code, alt, false))
        assertContentEquals(bytes(0x1b, '/'.code), KeyboardInput.encodeKeyDown('/'.code, alt, false))
        assertNull(KeyboardInput.encodeKeyDown('a'.code, none, false)) // plain text is typed text
        assertNull(KeyboardInput.encodeKeyDown('.'.code, alt, false)) // not in the base set
        assertNull(KeyboardInput.encodeKeyDown('é'.code, alt, false))
    }

    @Test
    fun macOptionComposesInsteadOfActingAsMeta() {
        assertNull(KeyboardInput.encodeKeyDown('b'.code, alt, optionComposes = true))
        assertContentEquals("å".encodeToByteArray(), KeyboardInput.encodeText("å", alt, false, optionComposes = true))
        // Ctrl is unaffected.
        assertContentEquals(bytes(3), KeyboardInput.encodeKeyDown('c'.code, ctrl, optionComposes = true))
    }

    @Test
    fun altGrCharactersAreSentAsPlainUtf8() {
        // Windows reports AltGr as Ctrl+Alt: AltGr+Q = '@', AltGr+ß = '\', AltGr+7 = '{', AltGr+E = '€'.
        for (s in listOf("@", "\\", "{", "[", "€", "~")) {
            assertContentEquals(s.encodeToByteArray(), KeyboardInput.encodeText(s, ctrlAlt, false, false), s)
            // The key-down for the same key must not also send something.
            assertNull(KeyboardInput.encodeKeyDown(s[0].code, ctrlAlt, false), s)
        }
    }

    @Test
    fun ctrlAltLetterIsStillACombinationNotAltGr() {
        assertContentEquals(bytes(0x1b, 2), KeyboardInput.encodeKeyDown('b'.code, ctrlAlt, false))
    }

    @Test
    fun typedTextIsPlainUtf8() {
        assertContentEquals("a".encodeToByteArray(), KeyboardInput.encodeText("a", none, false, false))
        assertContentEquals("A".encodeToByteArray(), KeyboardInput.encodeText("A", KeyModifiers(shift = true), false, false))
        assertContentEquals("é".encodeToByteArray(), KeyboardInput.encodeText("é", none, false, false))
        assertContentEquals("😀".encodeToByteArray(), KeyboardInput.encodeText("😀", none, false, false))
    }

    @Test
    fun typedTextRejectsControlsAndMultipleCodePoints() {
        assertNull(KeyboardInput.encodeText("", none, false, false))
        assertNull(KeyboardInput.encodeText("ab", none, false, false))
        assertNull(KeyboardInput.encodeText("\u0003", none, false, false))
        assertNull(KeyboardInput.encodeText("\u007f", none, false, false))
        assertNull(KeyboardInput.encodeText("\u0085", none, false, false))
        assertNull(KeyboardInput.encodeText("\uD83D", none, false, false)) // lone surrogate
    }

    @Test
    fun desktopTypedEventsWithCtrlOrHandledAltAreIgnored() {
        assertNull(KeyboardInput.encodeText("c", ctrl, combinationsFromText = false, optionComposes = false))
        assertNull(KeyboardInput.encodeText("b", alt, combinationsFromText = false, optionComposes = false))
        // Alt+. is not a key-down combination, so its typed event carries it.
        assertContentEquals(bytes(0x1b, '.'.code), KeyboardInput.encodeText(".", alt, false, false))
    }

    @Test
    fun androidTextCarriesCombinations() {
        assertContentEquals(bytes(3), KeyboardInput.encodeText("c", ctrl, combinationsFromText = true, optionComposes = false))
        assertContentEquals(bytes(0x1b, 'b'.code), KeyboardInput.encodeText("b", alt, true, false))
        assertContentEquals(bytes(0x1b, '.'.code), KeyboardInput.encodeText(".", alt, true, false))
        assertNull(KeyboardInput.encodeText(".", ctrl, true, false))
    }

    @Test
    fun singleCodePointDecodesSurrogatePairs() {
        assertEquals(0x1F600, KeyboardInput.singleCodePoint("😀"))
        assertEquals('a'.code, KeyboardInput.singleCodePoint("a"))
        assertNull(KeyboardInput.singleCodePoint("😀a"))
    }
}
