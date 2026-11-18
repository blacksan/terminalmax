// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import android.view.KeyCharacterMap
import androidx.compose.ui.input.key.KeyEvent
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.type
import android.view.KeyEvent as AndroidKeyEvent

internal actual fun createTypedTextState(): TypedTextState = TypedTextState(optionComposes = false)

internal actual fun typedText(event: KeyEvent, state: TypedTextState): TypedText? {
    if (event.type != KeyEventType.KeyDown) return null
    val native = event.nativeKeyEvent
    // Ask the key character map for the character without Ctrl/Alt/Meta so that Alt+b is "b" (the
    // handler then adds the ESC prefix) instead of the layout's Alt-layer character.
    val stripped = AndroidKeyEvent.META_CTRL_MASK or AndroidKeyEvent.META_ALT_MASK or AndroidKeyEvent.META_META_MASK
    var c = native.getUnicodeChar(native.metaState and stripped.inv())
    if (c == 0) return null
    if ((c and KeyCharacterMap.COMBINING_ACCENT) != 0) {
        // Dead key: remember the accent, combine it with the next character.
        state.pendingAccent = c and KeyCharacterMap.COMBINING_ACCENT_MASK
        return null
    }
    if (state.pendingAccent != 0) {
        val combined = KeyCharacterMap.getDeadChar(state.pendingAccent, c)
        state.pendingAccent = 0
        if (combined > 0) c = combined
    }
    if (c <= 0 || c > 0x10FFFF) return null
    return TypedText(Character.toChars(c).concatToString(), carriesCombinations = true)
}

internal actual fun isAltGraph(event: KeyEvent): Boolean = false
