// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** The host is untrusted: hostile output must not resize, hang, exhaust memory or kill the engine. */
class HostileInputTest {
    private val esc = "\u001b"
    private val bel = "\u0007"

    private fun engine(cols: Int = 20, rows: Int = 5) = createTerminalEngine(cols, rows)

    private fun TerminalEngine.feed(s: String) = feed(s.encodeToByteArray())

    private fun TerminalEngine.feedChunked(bytes: ByteArray, chunk: Int = 8192) {
        var off = 0
        while (off < bytes.size) {
            val n = minOf(chunk, bytes.size - off)
            feed(bytes, off, n)
            off += n
        }
    }

    private fun TerminalEngine.assertStillWorks() {
        feed("$esc[2J$esc[Hok")
        assertEquals("ok", snapshot().rowText(0))
    }

    private fun pending(e: TerminalEngine): Int = (e as JediTermEngine).pendingChars

    @Test
    fun remoteResizeRequestIsIgnored() {
        val e = engine(20, 5)
        e.feed("${esc}[8;9999;9999t")
        assertEquals(20, e.cols)
        assertEquals(5, e.rows)
        e.feed("${esc}[8;30;100t")
        assertEquals(20, e.cols)
        assertEquals(5, e.rows)
        val s = e.snapshot()
        assertEquals(20, s.cols)
        assertEquals(5, s.lines.size)
        e.assertStillWorks()
    }

    @Test
    fun localResizeIsClamped() {
        val e = engine(20, 5)
        e.resize(100_000, 100_000)
        assertEquals(TerminalLimits.MAX_COLS, e.cols)
        assertEquals(TerminalLimits.MAX_ROWS, e.rows)
        e.resize(-5, 0)
        assertEquals(TerminalLimits.MIN_COLS, e.cols)
        assertEquals(TerminalLimits.MIN_ROWS, e.rows)
        e.assertStillWorks()
    }

    @Test
    fun hugeInitialSizeIsClamped() {
        val e = createTerminalEngine(1_000_000, 1_000_000, 10)
        assertEquals(TerminalLimits.MAX_COLS, e.cols)
        assertEquals(TerminalLimits.MAX_ROWS, e.rows)
    }

    @Test
    fun unterminatedOneMiBOscInChunksIsFastAndBounded() {
        for (prefix in listOf("0;", "52;c;")) { // a title (4 KiB cap) and a generic OSC (64 KiB cap)
            val e = engine()
            val payload = ByteArray(1024 * 1024) { 'A'.code.toByte() }
            val start = System.nanoTime()
            e.feed("$esc]$prefix")
            var worst = 0
            var off = 0
            while (off < payload.size) {
                e.feed(payload, off, 8192)
                worst = maxOf(worst, pending(e))
                off += 8192
            }
            val seconds = (System.nanoTime() - start) / 1e9
            assertTrue(seconds < 5.0, "took $seconds s for prefix $prefix")
            assertTrue(worst <= 64 * 1024 + 2, "pending was $worst for prefix $prefix")
            // The terminator ends the discarded sequence and the engine carries on.
            e.feed("${bel}ok")
            assertEquals("ok", e.snapshot().rowText(0))
            assertEquals(null, e.snapshot().title)
        }
    }

    @Test
    fun oscBelowTheCapStillSetsTheTitleAfterChunkedDelivery() {
        val e = engine()
        e.feed("$esc]0;my ")
        e.feed("title$bel")
        assertEquals("my title", e.snapshot().title)
    }

    @Test
    fun unterminatedCsiFloodStaysBounded() {
        val e = engine()
        e.feed("$esc[")
        val chunk = ByteArray(8192) { ';'.code.toByte() }
        repeat(128) { e.feed(chunk) }
        assertTrue(pending(e) <= 300, "pending was ${pending(e)}")
        e.feed("m")
        e.assertStillWorks()
    }

    @Test
    fun csiWithHundredThousandParametersIsDropped() {
        val e = engine()
        val start = System.nanoTime()
        e.feed("$esc[" + "1;".repeat(100_000) + "mxy")
        assertTrue((System.nanoTime() - start) / 1e9 < 5.0)
        assertEquals("xy", e.snapshot().rowText(0))
        assertEquals(20, e.cols)
    }

    @Test
    fun hugeNumericParameterIsClamped() {
        val e = engine()
        e.feed("ab$esc[99999999999C")
        val s = e.snapshot()
        assertTrue(s.cursorCol in 0 until 20, "cursor at ${s.cursorCol}")
        assertEquals(20, e.cols)
        e.feed("$esc[99999999999;99999999999H")
        assertTrue(e.snapshot().cursorRow in 0 until 5)
        e.assertStillWorks()
    }

    @Test
    fun invalidUtf8NeverBreaksTheEngine() {
        val e = engine()
        val bytes = byteArrayOf(
            0xFF.toByte(), 0xFE.toByte(), 0xC0.toByte(), 0x80.toByte(), 'a'.code.toByte(),
            0xED.toByte(), 0xA0.toByte(), 0x80.toByte(), 'b'.code.toByte(),
            0xF8.toByte(), 0x88.toByte(), 0x80.toByte(), 0x80.toByte(), 0x80.toByte(),
            0xE4.toByte(), 0xB8.toByte(), // truncated 3-byte sequence at the end of the chunk
        )
        e.feed(bytes)
        val text = e.snapshot().rowText(0)
        assertTrue(text.contains('a') && text.contains('b'), "row was '$text'")
        e.feed("$esc[2J$esc[Hok")
        assertEquals("ok", e.snapshot().rowText(0))
    }

    @Test
    fun emojiKeepsLaterColumnsAlignedWithTheCursor() {
        val e = engine()
        e.feed("😀x")
        val s = e.snapshot()
        val row = s.lines[0]
        val emoji = row.indexOfFirst { it.text == "😀" }
        val x = row.indexOfFirst { it.text == "x" }
        assertEquals(0, emoji)
        assertEquals(2, row[emoji].width)
        assertEquals(0, row[emoji + 1].width)
        assertTrue(x > emoji + 1)
        assertEquals(20, row.size)
        // 'x' is the last thing written, so the cursor sits right after it.
        assertEquals(x + 1, s.cursorCol)
    }

    @Test
    fun emojiInTheMiddleOfAWideRowKeepsAlignment() {
        val e = engine(30, 3)
        e.feed("ab😀世c")
        val s = e.snapshot()
        val c = s.lines[0].indexOfFirst { it.text == "c" }
        assertEquals(c + 1, s.cursorCol)
    }

    @Test
    fun deviceStatusFloodWithBlockingCallbackDoesNotBlockSnapshot() {
        val e = engine()
        val delivered = AtomicInteger()
        val insideCallback = CountDownLatch(1)
        e.onResponse = {
            insideCallback.countDown()
            Thread.sleep(20)
            delivered.incrementAndGet()
        }
        e.snapshot() // warm up so JIT start-up is not mistaken for lock contention
        val count = 25
        val feeder = thread(name = "dsr-feeder") { e.feed("$esc[6n".repeat(count)) }
        assertTrue(insideCallback.await(10, java.util.concurrent.TimeUnit.SECONDS))
        var worstNanos = 0L
        var snapshots = 0
        while (feeder.isAlive) {
            val t0 = System.nanoTime()
            e.snapshot()
            e.cols
            worstNanos = maxOf(worstNanos, System.nanoTime() - t0)
            snapshots++
            Thread.sleep(1)
        }
        feeder.join()
        // The feeder spent >= 25 * 20 ms inside the callback; the lock must not have been held.
        assertTrue(snapshots > 5, "only $snapshots snapshots while responses were delivered")
        assertTrue(worstNanos / 1e6 < 250.0, "snapshot blocked for ${worstNanos / 1e6} ms")
        assertEquals(count, delivered.get())
    }

    @Test
    fun responseFloodWithoutConsumerIsBounded() {
        val e = engine()
        var bytes = 0
        e.onResponse = { bytes += it.size }
        // 1 MiB of DSR requests in one feed: far more responses than the engine is willing to queue.
        e.feed("$esc[6n".repeat(200_000))
        assertTrue(bytes <= 64 * 1024, "delivered $bytes bytes")
        assertTrue(bytes > 0)
        e.assertStillWorks()
    }

    @Test
    fun titleIsSanitisedAndCapped() {
        val e = engine()
        e.feed("$esc]0;a‮b\u0001c\u0085d$bel")
        assertEquals("abcd", e.snapshot().title)
        e.feed("$esc]2;" + "x".repeat(300) + bel)
        assertEquals(256, e.snapshot().title?.length)
    }

    @Test
    fun titleStackIsBoundedAndBalanced() {
        val e = engine()
        e.feed("$esc]0;first$bel")
        repeat(1000) { e.feed("$esc[22;0t") }
        e.feed("$esc]0;second$bel")
        repeat(2000) { e.feed("$esc[23;0t") } // more pops than pushes must not throw
        assertNotNull(e.snapshot())
        e.assertStillWorks()
    }

    @Test
    fun c1ControlsAndStringSequencesDoNotReachTheScreen() {
        val e = engine()
        e.feed("a\u009bb$esc" + "Psecret$esc\\c${esc}_apc${bel}d")
        assertEquals("abcd", e.snapshot().rowText(0))
    }
}
