// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlinx.coroutines.flow.StateFlow

/**
 * A headless VT emulator. All methods are thread-safe: [feed] may run on an IO coroutine while
 * [snapshot] is read from the UI thread.
 */
interface TerminalEngine {
    val cols: Int
    val rows: Int

    /** Incremented whenever the visible screen changes (output, resize). */
    val revision: StateFlow<Long>

    /**
     * Bytes the emulator wants sent back to the host (device status/attribute reports).
     * May be invoked from the thread that calls [feed].
     */
    var onResponse: ((ByteArray) -> Unit)?

    /** Feed raw host output. UTF-8 sequences and escape sequences may be split across calls. */
    fun feed(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size)

    fun resize(cols: Int, rows: Int)

    fun snapshot(): TerminalSnapshot

    /** Bytes to send to the host for [key] given the engine's current cursor-key mode. */
    fun encodeKey(key: TerminalKey, modifiers: KeyModifiers = KeyModifiers.None): ByteArray

    fun close()
}
