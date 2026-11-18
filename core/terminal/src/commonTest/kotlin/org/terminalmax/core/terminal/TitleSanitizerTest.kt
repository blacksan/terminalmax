// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

import kotlin.test.Test
import kotlin.test.assertEquals

class TitleSanitizerTest {
    @Test
    fun plainTitleIsUnchanged() {
        assertEquals("[admin@MikroTik] > ", TitleSanitizer.sanitize("[admin@MikroTik] > "))
    }

    @Test
    fun controlsAndBidiOverridesAreStripped() {
        assertEquals("abc", TitleSanitizer.sanitize("a\u0001b\u007f\u0085c\u009f"))
        assertEquals("abc", TitleSanitizer.sanitize("a‮b‪c‫‬‭"))
        assertEquals("abc", TitleSanitizer.sanitize("a⁦b⁧⁨⁩c"))
        assertEquals("ab", TitleSanitizer.sanitize("a\r\nb"))
        assertEquals("é世", TitleSanitizer.sanitize("é世"))
    }

    @Test
    fun titleIsTruncatedTo256Characters() {
        assertEquals(256, TitleSanitizer.sanitize("x".repeat(10_000)).length)
        // Stripped characters do not use up the budget.
        assertEquals(256, TitleSanitizer.sanitize("\u0001".repeat(100) + "x".repeat(300)).length)
    }

    @Test
    fun truncationNeverSplitsASurrogatePair() {
        val s = TitleSanitizer.sanitize("x".repeat(255) + "😀")
        assertEquals(255, s.length)
    }
}
