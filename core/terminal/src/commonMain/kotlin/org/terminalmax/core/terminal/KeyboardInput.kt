// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.terminal

/**
 * Pure keyboard rules shared by every platform; the platform-specific parts (how to read typed
 * text from an event) live in `PlatformKeys`.
 *
 * Keyboard model:
 * - Printable text comes from *typed-character* events (AWT `KEY_TYPED` on desktop, the unicode
 *   character of the key on Android), never from the character of a raw key-down. That is what
 *   makes dead keys, AltGr and layouts work.
 * - Key-down is used only for special keys (arrows, F-keys, ...) and for Ctrl/Alt combinations
 *   with ASCII letters, digits or `@ [ \ ] ^ _ space / ? `` ` ``.
 * - AltGr rule: Ctrl+Alt (how Windows reports AltGr) with a printable non-ASCII-letter character
 *   sends the character itself as plain UTF-8, without modifiers.
 * - Meta/Cmd-modified keys are never sent.
 */
internal object KeyboardInput {
    /** True for values that are not characters: negatives, U+FFFF/U+FFFE (AWT CHAR_UNDEFINED), U+FDD0..FDEF, surrogates, > U+10FFFF. */
    fun isNonCharacter(cp: Int): Boolean =
        cp < 0 || cp > 0x10FFFF || cp in 0xD800..0xDFFF || cp in 0xFDD0..0xFDEF || (cp and 0xFFFE) == 0xFFFE

    /** A real character that can be shown: not a control (C0, DEL, C1) and not a non-character. */
    fun isPrintable(cp: Int): Boolean =
        !isNonCharacter(cp) && cp >= 0x20 && cp != 0x7F && cp !in 0x80..0x9F

    fun isAsciiLetter(cp: Int): Boolean = cp in 'a'.code..'z'.code || cp in 'A'.code..'Z'.code

    /** Base characters for which Ctrl/Alt combinations are handled from the key-down event. */
    fun isCombinationBase(cp: Int): Boolean =
        isAsciiLetter(cp) || cp in '0'.code..'9'.code || (cp < 0x80 && COMBINATION_SYMBOLS.indexOf(cp.toChar()) >= 0)

    /**
     * Bytes for a key-down with Ctrl and/or Alt, [cp] being the character the platform reports for
     * the key (already control-translated by AWT for Ctrl combinations). Returns null when the
     * key-down must be ignored (the typed-character event handles it, or it is not a combination).
     */
    fun encodeKeyDown(cp: Int, m: KeyModifiers, optionComposes: Boolean): ByteArray? {
        if (!m.ctrl && !m.alt) return null
        if (isNonCharacter(cp)) return null
        // AltGr (Ctrl+Alt on Windows): the character arrives as typed text.
        if (m.ctrl && m.alt && isPrintable(cp) && !isAsciiLetter(cp)) return null
        // macOS Option composes characters; the typed event delivers them.
        if (!m.ctrl && m.alt && optionComposes) return null
        if (m.ctrl && cp in 0..0x1F) return XtermKeyEncoder.encodeCodePoint(cp, m)
        if (isCombinationBase(cp)) return XtermKeyEncoder.encodeCodePoint(cp, m)
        return null
    }

    /**
     * Bytes for typed [text] (one code point). [combinationsFromText] is true on platforms where
     * the typed text is delivered with a key-down (Android): Ctrl/Alt combinations are then encoded
     * here; on desktop they were already handled by [encodeKeyDown].
     */
    fun encodeText(
        text: String,
        m: KeyModifiers,
        combinationsFromText: Boolean,
        optionComposes: Boolean,
    ): ByteArray? {
        val cp = singleCodePoint(text) ?: return null
        if (!isPrintable(cp)) return null
        if (m.ctrl && m.alt) {
            if (!isAsciiLetter(cp)) return plain(cp) // AltGr
            return if (combinationsFromText) XtermKeyEncoder.encodeCodePoint(cp, m) else null
        }
        if (m.ctrl) {
            return if (combinationsFromText && isCombinationBase(cp)) XtermKeyEncoder.encodeCodePoint(cp, m) else null
        }
        if (m.alt) {
            if (optionComposes) return plain(cp)
            if (combinationsFromText) return XtermKeyEncoder.encodeCodePoint(cp, m)
            // Desktop: combinations of the base set were sent from the key-down; only the rest comes here.
            return if (isCombinationBase(cp)) null else XtermKeyEncoder.encodeCodePoint(cp, m)
        }
        return plain(cp)
    }

    /** The only code point of [text], or null if it is empty or longer. */
    fun singleCodePoint(text: String): Int? = when {
        text.length == 1 -> text[0].code
        text.length == 2 && text[0].isHighSurrogate() && text[1].isLowSurrogate() ->
            0x10000 + ((text[0].code - 0xD800) shl 10) + (text[1].code - 0xDC00)
        else -> null
    }

    private fun plain(cp: Int): ByteArray? = XtermKeyEncoder.encodeCodePoint(cp, KeyModifiers.None)

    private const val COMBINATION_SYMBOLS = "@[\\]^_ /?`"
}
