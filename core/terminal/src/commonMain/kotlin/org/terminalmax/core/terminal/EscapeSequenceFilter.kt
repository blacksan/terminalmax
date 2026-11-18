// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

/**
 * Pre-filter that sits in front of the emulator and bounds everything a hostile host can make the
 * emulator buffer or compute. It is a small VT500-style state machine over UTF-16 characters.
 *
 * Contract: the output contains only plain text and **complete** escape sequences. Incomplete
 * sequences are held here, in buffers with hard caps ([pendingLength] never exceeds
 * [MAX_PENDING]), so the emulator itself never has to wait for the rest of a sequence.
 *
 * Rules:
 * - CSI: at most [MAX_CSI_LENGTH] parameter/intermediate characters and [MAX_CSI_PARAMS]
 *   parameters (`;` and `:` separate parameters). A longer or more crowded sequence is dropped
 *   whole. Every number is clamped to [MAX_PARAM_VALUE] by rewriting its digits.
 * - OSC: payload at most [MAX_STRING_PAYLOAD] characters, or [MAX_TITLE_PAYLOAD] for the title
 *   commands 0, 1 and 2. A longer OSC is dropped whole: the rest of it is discarded up to its
 *   terminator without being buffered or forwarded. Terminated OSC is forwarded normalised as
 *   `ESC ] payload BEL`.
 * - DCS, APC, PM and SOS strings are never forwarded (not supported); they are skipped up to
 *   their terminator without buffering.
 * - String terminators are BEL, `ESC \` and U+009C. `ESC` followed by anything else inside a
 *   string aborts the string and starts a new escape sequence. CAN and SUB abort a sequence.
 * - C1 control characters (U+0080..U+009F) are never forwarded.
 * - Other short escape sequences (`ESC`, up to [MAX_ESC_INTERMEDIATES] intermediates, a final)
 *   are forwarded once complete. Control characters inside an escape sequence are executed in
 *   place (forwarded immediately), as terminals do.
 *
 * Not thread-safe; the engine calls it under its lock.
 */
internal class EscapeSequenceFilter {
    private enum class State { Ground, Esc, EscIntermediate, Csi, CsiDiscard, Osc, OscEsc, Skip, SkipEsc }

    private var state = State.Ground
    private val csi = StringBuilder()
    private val osc = StringBuilder()
    private val escIntermediates = StringBuilder()
    private var escOverflow = false
    private var oscIsTitle = false
    private var oscTitleDecided = false

    /** Characters currently held back (an unfinished sequence). Always <= [MAX_PENDING]. */
    val pendingLength: Int
        get() = when (state) {
            State.Ground, State.CsiDiscard, State.Skip, State.SkipEsc -> 0
            State.Esc -> 1
            State.EscIntermediate -> 1 + escIntermediates.length
            State.Csi -> 2 + csi.length
            State.Osc, State.OscEsc -> 2 + osc.length
        }

    fun reset() {
        state = State.Ground
        csi.setLength(0)
        osc.setLength(0)
        escIntermediates.setLength(0)
        escOverflow = false
    }

    /** Filters `input[0 until length]`, appending the safe characters to [out]. */
    fun filter(input: CharArray, length: Int, out: StringBuilder) {
        require(length in 0..input.size) { "Bad length" }
        for (i in 0 until length) accept(input[i], out)
    }

    fun filter(input: String, out: StringBuilder) {
        for (i in input.indices) accept(input[i], out)
    }

    private fun accept(c: Char, out: StringBuilder) {
        when (state) {
            State.Ground -> ground(c, out)
            State.Esc -> esc(c, out)
            State.EscIntermediate -> escIntermediate(c, out)
            State.Csi -> csiChar(c, out)
            State.CsiDiscard -> csiDiscard(c, out)
            State.Osc -> oscChar(c, out)
            State.OscEsc -> oscEsc(c, out)
            State.Skip -> skip(c)
            State.SkipEsc -> skipEsc(c, out)
        }
    }

    private fun ground(c: Char, out: StringBuilder) {
        when {
            c == ESC -> state = State.Esc
            c.code in 0x80..0x9F -> Unit // C1 controls are never forwarded
            else -> out.append(c)
        }
    }

    private fun esc(c: Char, out: StringBuilder) {
        val code = c.code
        when {
            c == '[' -> {
                csi.setLength(0)
                state = State.Csi
            }
            c == ']' -> {
                osc.setLength(0)
                oscIsTitle = false
                oscTitleDecided = false
                state = State.Osc
            }
            c == 'P' || c == 'X' || c == '^' || c == '_' -> state = State.Skip
            c == ESC -> Unit
            c == CAN || c == SUB -> state = State.Ground
            code < 0x20 -> out.append(c)
            code == 0x7F -> Unit
            code in 0x20..0x2F -> {
                escIntermediates.setLength(0)
                escIntermediates.append(c)
                escOverflow = false
                state = State.EscIntermediate
            }
            code in 0x30..0x7E -> {
                out.append(ESC).append(c)
                state = State.Ground
            }
            else -> {
                state = State.Ground
                ground(c, out)
            }
        }
    }

    private fun escIntermediate(c: Char, out: StringBuilder) {
        val code = c.code
        when {
            c == ESC -> {
                escIntermediates.setLength(0)
                state = State.Esc
            }
            c == CAN || c == SUB -> {
                escIntermediates.setLength(0)
                state = State.Ground
            }
            code < 0x20 -> out.append(c)
            code == 0x7F -> Unit
            code in 0x20..0x2F -> {
                if (escIntermediates.length < MAX_ESC_INTERMEDIATES) escIntermediates.append(c) else escOverflow = true
            }
            code in 0x30..0x7E -> {
                if (!escOverflow) out.append(ESC).append(escIntermediates).append(c)
                escIntermediates.setLength(0)
                state = State.Ground
            }
            else -> {
                escIntermediates.setLength(0)
                state = State.Ground
                ground(c, out)
            }
        }
    }

    private fun csiChar(c: Char, out: StringBuilder) {
        val code = c.code
        when {
            c == ESC -> {
                csi.setLength(0)
                state = State.Esc
            }
            c == CAN || c == SUB -> {
                csi.setLength(0)
                state = State.Ground
            }
            code < 0x20 -> out.append(c)
            code == 0x7F -> Unit
            code in 0x20..0x3F -> {
                if (csi.length >= MAX_CSI_LENGTH) {
                    csi.setLength(0)
                    state = State.CsiDiscard
                } else {
                    csi.append(c)
                }
            }
            code in 0x40..0x7E -> {
                emitCsi(c, out)
                csi.setLength(0)
                state = State.Ground
            }
            else -> {
                csi.setLength(0)
                state = State.Ground
                ground(c, out)
            }
        }
    }

    private fun csiDiscard(c: Char, out: StringBuilder) {
        val code = c.code
        when {
            c == ESC -> state = State.Esc
            c == CAN || c == SUB -> state = State.Ground
            code < 0x20 -> out.append(c)
            code in 0x40..0x7E -> state = State.Ground
            code < 0x80 -> Unit // parameter, intermediate or DEL: still discarding
            else -> {
                state = State.Ground
                ground(c, out)
            }
        }
    }

    private fun emitCsi(final: Char, out: StringBuilder) {
        var separators = 0
        for (i in 0 until csi.length) {
            val ch = csi[i]
            if (ch == ';' || ch == ':') separators++
        }
        if (separators + 1 > MAX_CSI_PARAMS) return // too many parameters: dropped whole
        out.append(ESC).append('[')
        var i = 0
        while (i < csi.length) {
            val ch = csi[i]
            if (ch in '0'..'9') {
                var value = 0
                while (i < csi.length && csi[i] in '0'..'9') {
                    value = value * 10 + (csi[i] - '0')
                    if (value > MAX_PARAM_VALUE) value = MAX_PARAM_VALUE
                    i++
                }
                out.append(value.toString())
            } else {
                out.append(ch)
                i++
            }
        }
        out.append(final)
    }

    private fun oscChar(c: Char, out: StringBuilder) {
        when {
            c == BEL || c == ST_C1 -> finishOsc(out)
            c == ESC -> state = State.OscEsc
            c == CAN || c == SUB -> {
                osc.setLength(0)
                state = State.Ground
            }
            else -> {
                osc.append(c)
                if (!oscTitleDecided && c == ';') {
                    oscTitleDecided = true
                    // osc now holds "<Ps>;"
                    oscIsTitle = osc.length == 2 && osc[0] in '0'..'2'
                }
                val limit = if (oscIsTitle) MAX_TITLE_PAYLOAD else MAX_STRING_PAYLOAD
                if (osc.length > limit) {
                    osc.setLength(0)
                    state = State.Skip
                }
            }
        }
    }

    private fun oscEsc(c: Char, out: StringBuilder) {
        if (c == '\\') {
            finishOsc(out)
        } else {
            osc.setLength(0)
            state = State.Esc
            esc(c, out)
        }
    }

    private fun finishOsc(out: StringBuilder) {
        out.append(ESC).append(']').append(osc).append(BEL)
        osc.setLength(0)
        state = State.Ground
    }

    private fun skip(c: Char) {
        when {
            c == BEL || c == ST_C1 || c == CAN || c == SUB -> state = State.Ground
            c == ESC -> state = State.SkipEsc
        }
    }

    private fun skipEsc(c: Char, out: StringBuilder) {
        when {
            c == '\\' -> state = State.Ground
            c == ESC -> Unit
            else -> {
                state = State.Esc
                esc(c, out)
            }
        }
    }

    companion object {
        const val MAX_CSI_LENGTH = 256
        const val MAX_CSI_PARAMS = 32
        const val MAX_PARAM_VALUE = 65535
        const val MAX_STRING_PAYLOAD = 64 * 1024
        const val MAX_TITLE_PAYLOAD = 4 * 1024
        const val MAX_ESC_INTERMEDIATES = 4

        /** Hard upper bound of [pendingLength]: the largest OSC plus its two-character introducer. */
        const val MAX_PENDING = MAX_STRING_PAYLOAD + 2

        private const val ESC = '\u001b'
        private const val BEL = '\u0007'
        private const val CAN = '\u0018'
        private const val SUB = '\u001a'
        private const val ST_C1 = '\u009c'
    }
}
