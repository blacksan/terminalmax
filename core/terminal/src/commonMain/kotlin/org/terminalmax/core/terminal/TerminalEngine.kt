// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlinx.coroutines.flow.StateFlow

/** Size bounds every [TerminalEngine] enforces, regardless of what the caller or the host asks for. */
object TerminalLimits {
    const val MIN_COLS = 2
    const val MAX_COLS = 1000
    const val MIN_ROWS = 2
    const val MAX_ROWS = 500
}

/**
 * A headless VT emulator for **untrusted** host output. All methods are thread-safe: [feed] may run
 * on an IO coroutine while [snapshot] is read from the UI thread.
 *
 * Security contract: the host can never change the terminal size (window-manipulation resize
 * requests are ignored), can never make the engine buffer more than a bounded amount of an
 * unfinished escape sequence, and window titles are sanitised before they reach [TerminalSnapshot.title].
 */
interface TerminalEngine {
    /** Current width in cells, always within [TerminalLimits.MIN_COLS]..[TerminalLimits.MAX_COLS]. */
    val cols: Int

    /** Current height in cells, always within [TerminalLimits.MIN_ROWS]..[TerminalLimits.MAX_ROWS]. */
    val rows: Int

    /** Incremented whenever the visible screen changes (output, resize). */
    val revision: StateFlow<Long>

    /**
     * Bytes the emulator wants sent back to the host (device status/attribute reports).
     *
     * Invoked on the thread that calls [feed] (or [resize]), after the engine's internal locks have
     * been released: never called while internal locks are held; must not block. Hand the bytes to
     * a bounded queue and return. The engine itself drops responses beyond a small per-call budget,
     * so a host that floods status requests cannot grow memory.
     */
    var onResponse: ((ByteArray) -> Unit)?

    /** Feed raw host output. UTF-8 sequences and escape sequences may be split across calls. */
    fun feed(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size)

    /**
     * Resizes the screen. [cols] and [rows] are clamped to [TerminalLimits]. Only local callers can
     * resize; the host's `CSI 8 ; rows ; cols t` is ignored.
     */
    fun resize(cols: Int, rows: Int)

    fun snapshot(): TerminalSnapshot

    /** Bytes to send to the host for [key] given the engine's current cursor-key mode. */
    fun encodeKey(key: TerminalKey, modifiers: KeyModifiers = KeyModifiers.None): ByteArray

    fun close()
}
