// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

/** Window titles come from the remote host: strip control and bidi-override characters and cap the length. */
internal object TitleSanitizer {
    const val MAX_TITLE_LENGTH = 256

    fun sanitize(raw: String): String {
        val sb = StringBuilder(minOf(raw.length, MAX_TITLE_LENGTH))
        for (ch in raw) {
            if (isForbidden(ch)) continue
            if (sb.length >= MAX_TITLE_LENGTH) break
            sb.append(ch)
        }
        // Never leave half of a surrogate pair at the cut.
        if (sb.isNotEmpty() && sb[sb.length - 1].isHighSurrogate()) sb.setLength(sb.length - 1)
        return sb.toString()
    }

    private fun isForbidden(ch: Char): Boolean {
        val c = ch.code
        return c < 0x20 || c in 0x7F..0x9F || c in 0x202A..0x202E || c in 0x2066..0x2069
    }
}
