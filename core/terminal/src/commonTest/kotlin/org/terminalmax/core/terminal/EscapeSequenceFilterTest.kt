// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EscapeSequenceFilterTest {
    private val esc = "\u001b"
    private val bel = "\u0007"

    private fun run(vararg chunks: String, filter: EscapeSequenceFilter = EscapeSequenceFilter()): String {
        val out = StringBuilder()
        for (chunk in chunks) filter.filter(chunk, out)
        return out.toString()
    }

    @Test
    fun plainTextPassesThrough() {
        assertEquals("hello, world\r\n", run("hello, world\r\n"))
    }

    @Test
    fun ordinaryCsiPassesThroughUnchanged() {
        assertEquals("$esc[31m", run("$esc[31m"))
        assertEquals("$esc[1;2;3H", run("$esc[1;2;3H"))
        assertEquals("$esc[?25l", run("$esc[?25l"))
        assertEquals("$esc[38;2;10;20;30m", run("$esc[38;2;10;20;30m"))
        assertEquals("$esc[38:2::10:20:30m", run("$esc[38:2::10:20:30m"))
    }

    @Test
    fun csiSplitAcrossChunksIsHeldBackUntilComplete() {
        val f = EscapeSequenceFilter()
        val out = StringBuilder()
        f.filter("a$esc[3", out)
        assertEquals("a", out.toString())
        assertTrue(f.pendingLength > 0)
        f.filter("1mb", out)
        assertEquals("a$esc[31mb", out.toString())
        assertEquals(0, f.pendingLength)
    }

    @Test
    fun numericParametersAreClampedTo65535() {
        assertEquals("$esc[65535C", run("$esc[99999999999C"))
        assertEquals("$esc[65535;65535H", run("$esc[70000;65536H"))
        assertEquals("$esc[65535C", run("$esc[65535C"))
        assertEquals("$esc[7m", run("$esc[007m"))
        assertEquals("$esc[65535C", run("$esc[" + "9".repeat(200) + "C"))
    }

    @Test
    fun moreThan32ParametersDropTheSequence() {
        val ok = (1..32).joinToString(";")
        val tooMany = (1..33).joinToString(";")
        assertEquals("$esc[${ok}m", run("$esc[${ok}m"))
        assertEquals("x", run("$esc[${tooMany}mx"))
        // A hostile 100 000 parameter sequence is also bounded by the length cap.
        assertEquals("x", run("$esc[" + "1;".repeat(100_000) + "mx"))
    }

    @Test
    fun overlongCsiIsDroppedWithoutBuffering() {
        val f = EscapeSequenceFilter()
        val out = StringBuilder()
        f.filter("$esc[", out)
        var worst = 0
        repeat(1000) {
            f.filter("1".repeat(1000), out)
            worst = maxOf(worst, f.pendingLength)
        }
        assertTrue(worst <= EscapeSequenceFilter.MAX_CSI_LENGTH + 2, "pending was $worst")
        f.filter("mok", out)
        assertEquals("ok", out.toString())
    }

    @Test
    fun oscIsForwardedNormalisedToBel() {
        assertEquals("$esc]0;title$bel", run("$esc]0;title$bel"))
        assertEquals("$esc]0;title$bel", run("$esc]0;title$esc\\"))
        assertEquals("$esc]0;title$bel", run("$esc]0;title\u009c"))
    }

    @Test
    fun titleOscLongerThan4KiBIsDropped() {
        val long = "a".repeat(EscapeSequenceFilter.MAX_TITLE_PAYLOAD + 10)
        assertEquals("x", run("$esc]0;$long${bel}x"))
        assertEquals("x", run("$esc]2;$long${esc}\\x"))
        val fits = "a".repeat(EscapeSequenceFilter.MAX_TITLE_PAYLOAD - 10)
        assertEquals("$esc]0;$fits$bel", run("$esc]0;$fits$bel"))
    }

    @Test
    fun otherOscMayBeLargerButNotBeyond64KiB() {
        val fits = "a".repeat(5000)
        assertEquals("$esc]52;c;$fits$bel", run("$esc]52;c;$fits$bel"))
        val long = "a".repeat(EscapeSequenceFilter.MAX_STRING_PAYLOAD + 10)
        assertEquals("x", run("$esc]52;c;$long${bel}x"))
    }

    @Test
    fun unterminatedStringIsDiscardedAndPendingStaysBounded() {
        val f = EscapeSequenceFilter()
        val out = StringBuilder()
        f.filter("$esc]52;c;", out)
        var worst = 0
        repeat(256) {
            f.filter("A".repeat(8192), out)
            worst = maxOf(worst, f.pendingLength)
        }
        assertTrue(worst <= EscapeSequenceFilter.MAX_PENDING, "pending was $worst")
        assertEquals("", out.toString())
        f.filter("${bel}ok", out)
        assertEquals("ok", out.toString())
    }

    @Test
    fun dcsApcPmSosAreSwallowed() {
        assertEquals("x", run("$esc" + "P1\$r0m$esc\\x"))
        assertEquals("x", run("$esc" + "_payload$esc\\x"))
        assertEquals("x", run("$esc" + "^payload$esc\\x"))
        assertEquals("x", run("$esc" + "Xpayload${bel}x"))
    }

    @Test
    fun escapeInsideStringAbortsItAndStartsNewSequence() {
        assertEquals("$esc[31mx", run("$esc]0;ab$esc[31mx"))
        assertEquals("$esc[31mx", run("$esc" + "Pdata$esc[31mx"))
    }

    @Test
    fun c1ControlsAreNeverForwarded() {
        assertEquals("ab", run("a\u009bb"))
        assertEquals("ab", run("a\u009db"))
    }

    @Test
    fun shortEscapeSequencesPassOnceComplete() {
        assertEquals("$esc(B", run("$esc(B"))
        assertEquals("$esc#8", run("$esc#8"))
        assertEquals("${esc}7", run("${esc}7"))
        // Too many intermediates: dropped.
        assertEquals("x", run("$esc(((((((Bx"))
    }

    @Test
    fun cancelAbortsASequenceAndControlsRunInPlace() {
        assertEquals("1", run("$esc[3\u00181"))
        assertEquals("\n$esc[31m", run("$esc[3\n1m"))
    }

    @Test
    fun resultIsIdenticalRegardlessOfChunking() {
        val input = "a$esc[1;31mred$esc[0m$esc]0;t${bel}b$esc[99999999999Cc$esc(Bd"
        val whole = run(input)
        val f = EscapeSequenceFilter()
        val out = StringBuilder()
        for (ch in input) f.filter(ch.toString(), out)
        assertEquals(whole, out.toString())
    }
}
