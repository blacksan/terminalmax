// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import androidx.compose.ui.input.key.KeyEvent

/** Text delivered by a key event. [carriesCombinations] is true when Ctrl/Alt combinations must be encoded from it. */
internal class TypedText(val text: String, val carriesCombinations: Boolean)

/** Per-view mutable state the platform actuals need (dead keys, surrogate halves) and platform policy. */
internal class TypedTextState(
    /** macOS: Option composes characters instead of acting as Meta. */
    val optionComposes: Boolean,
) {
    /** Android: pending dead-key accent (a combining accent code point), 0 if none. */
    var pendingAccent: Int = 0

    /** Desktop: high surrogate of a supplementary character whose low half has not arrived yet. */
    var pendingHighSurrogate: Char = '\u0000'
}

internal expect fun createTypedTextState(): TypedTextState

/**
 * Printable text carried by [event], or null. Desktop: only AWT `KEY_TYPED` events (they reach the
 * key handlers as `KeyEventType.Unknown`). Android: key-downs, with Ctrl/Alt/Meta removed from the
 * meta state and dead keys combined.
 */
internal expect fun typedText(event: KeyEvent, state: TypedTextState): TypedText?

/** True when AltGr (AltGraph) is held. Only desktop can tell; Android reports false. */
internal expect fun isAltGraph(event: KeyEvent): Boolean
