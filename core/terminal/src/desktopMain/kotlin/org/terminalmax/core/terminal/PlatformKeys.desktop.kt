// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import androidx.compose.ui.awt.awtEventOrNull
import androidx.compose.ui.input.key.KeyEvent
import java.awt.event.KeyEvent as AwtKeyEvent

internal actual fun createTypedTextState(): TypedTextState =
    TypedTextState(optionComposes = System.getProperty("os.name").orEmpty().startsWith("Mac", ignoreCase = true))

internal actual fun typedText(event: KeyEvent, state: TypedTextState): TypedText? {
    // Compose desktop maps AWT KEY_TYPED to KeyEventType.Unknown; the original AWT event carries the character.
    val awt = event.awtEventOrNull ?: return null
    if (awt.id != AwtKeyEvent.KEY_TYPED) return null
    val ch = awt.keyChar
    val text = when {
        ch.isHighSurrogate() -> {
            state.pendingHighSurrogate = ch
            return null
        }
        ch.isLowSurrogate() -> {
            val high = state.pendingHighSurrogate
            state.pendingHighSurrogate = '\u0000'
            if (high == '\u0000') return null
            charArrayOf(high, ch).concatToString()
        }
        else -> {
            state.pendingHighSurrogate = '\u0000'
            // Control characters (Ctrl+C arrives as 0x03) are handled from the key-down.
            if (ch == AwtKeyEvent.CHAR_UNDEFINED || ch.isISOControl()) return null
            ch.toString()
        }
    }
    return TypedText(text, carriesCombinations = false)
}

internal actual fun isAltGraph(event: KeyEvent): Boolean = event.awtEventOrNull?.isAltGraphDown == true
