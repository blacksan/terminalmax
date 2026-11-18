// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.proof

private const val ESC = "\u001b"

/** Canned ANSI output used by the proof screen to exercise the terminal renderer. */
internal fun terminalDemoBytes(): ByteArray = buildString {
    append("${ESC}[1mTerminalMax terminal spike${ESC}[0m\r\n")
    // 16 ANSI colours, normal then bright.
    for (i in 0..7) append("${ESC}[4${i}m  ${ESC}[0m")
    append("\r\n")
    for (i in 0..7) append("${ESC}[10${i}m  ${ESC}[0m")
    append("\r\n")
    // A slice of the 256-colour cube and a truecolour gradient.
    for (i in 16..51) append("${ESC}[48;5;${i}m ${ESC}[0m")
    append("\r\n")
    for (i in 0..35) append("${ESC}[48;2;${i * 7};${255 - i * 7};160m ${ESC}[0m")
    append("\r\n")
    append("${ESC}[1mbold${ESC}[0m ${ESC}[3mitalic${ESC}[0m ${ESC}[4munderline${ESC}[0m ")
    append("${ESC}[7minverse${ESC}[0m ${ESC}[2mdim${ESC}[0m ${ESC}[31mred${ESC}[0m ")
    append("${ESC}[38;2;255;165;0mtruecolour${ESC}[0m\r\n")
    // Box drawing and a wide character.
    append("┌──────────┐\r\n")
    append("│ box 世界 │\r\n")
    append("└──────────┘\r\n")
    append("${ESC}[1;32m[admin@MikroTik]${ESC}[0m ${ESC}[1m>${ESC}[0m ")
}.encodeToByteArray()

/** Local echo for the demo: what a remote line discipline would print for typed bytes. */
internal fun terminalDemoEcho(input: ByteArray): ByteArray = when {
    input.size == 1 && input[0] == '\r'.code.toByte() -> "\r\n${ESC}[1;32m[admin@MikroTik]${ESC}[0m ${ESC}[1m>${ESC}[0m ".encodeToByteArray()
    input.size == 1 && input[0] == 0x7f.toByte() -> "\b \b".encodeToByteArray()
    input.isNotEmpty() && input[0] == 0x1b.toByte() -> ByteArray(0) // ignore escape sequences (arrows, F-keys)
    else -> input
}
