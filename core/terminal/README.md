# :core:terminal (spike)

Architecture under test: **one shared Compose Canvas renderer over one emulator engine behind an
interface**, used unchanged on Android and desktop.

## Engine decision: JediTerm core (`jediterm-core`)

Evidence gathered from github.com/JetBrains/jediterm (master) and the JetBrains Maven repository:

| Question | Finding |
| --- | --- |
| AWT-free core? | Yes. `settings.gradle.kts` has `:core`, `:ui`, `:JediTerm`; the Swing UI lives in `:ui`. In `:core` the files read (`JediTerminal`, `JediEmulator`, `TerminalTextBuffer`, `StyleState`, `TerminalDisplay`, `TerminalDataStream`, `ArrayTerminalDataStream`, `TextStyle`, `TerminalColor`, `TerminalLine`, `CharBuffer`, `Terminal`, `Platform`, `core.Color`, `core.util.TermSize`) import only `java.util`, `java.io`, `java.nio`, `java.text.Normalizer`, `kotlin`, slf4j and JetBrains annotations. `com.jediterm.core.Color` is a self-contained RGB class replacing `java.awt.Color`. The full `core/src` tree was not grepped (GitHub tree pages and archive download are blocked from the build machine). |
| Coordinates | `org.jetbrains.jediterm:jediterm-core:3.76` (maven-metadata: latest = release = 3.76, 75 versions). |
| Repository | **Not** Maven Central. Published to `https://packages.jetbrains.team/maven/p/ij/intellij-dependencies` (see `core/build.gradle.kts` `publishing`). No hit on `repo1.maven.org` was obtained (lookups were blocked/unavailable), so it is assumed absent. |
| License | README: dual-licensed **LGPLv3 or Apache-2.0**, user's choice. The published POM lists only "LGPL 3.0". |
| Bytecode / deps | Java and Kotlin compiled for JVM 11. `implementation` deps: `org.slf4j:slf4j-api:2.0.9`, `org.jetbrains:annotations:24.0.1`; Kotlin stdlib (compiled with Kotlin 2.4.0). |
| Android hazards | `Color.toXParseColor` uses `String.repeat` (API 34 / needs desugaring) but is only called for OSC colour queries. `Platform` reads `os.name` (works, returns Linux). No `java.awt`/`javax.swing` found in the files read. Java 11 bytecode is handled by D8. |

Alternative checked: `com.risaboss:bossterm-core(-android)` on central.sonatype.com. The Sonatype page is a
JavaScript app and returned no content to the fetch tool, so existence, version and license could
**not** be confirmed; it was not used. Decision rule applied: JediTerm core is AWT-free and
resolvable from a public Maven repository, so it is used; no built-in fallback engine was written.

### License implication

The app is GPL-3.0-or-later. JediTerm may be used under Apache-2.0 or LGPLv3; both are compatible
with GPLv3 (Apache-2.0 one-way into GPLv3, LGPLv3 explicitly). Choose and record the Apache-2.0
option in the third-party notices; keep the NOTICE/attribution text of the jar.

### Required repository (coordinator action)

`FAIL_ON_PROJECT_REPOS` is on, so the repository must be declared in `settings.gradle.kts`
`dependencyResolutionManagement.repositories`:

```kotlin
exclusiveContent {
    forRepository {
        maven { url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies") }
    }
    filter { includeGroup("org.jetbrains.jediterm") }
}
```

`exclusiveContent` pins the group to that repository: it is never probed on `google()` or
`mavenCentral()` (no dependency-confusion window), and nothing else is resolved from it.

## Interface

`TerminalEngine` (commonMain): `cols`, `rows`, `feed(bytes, offset, length)` (UTF-8 and escape
sequences may be split across calls), `resize`, `snapshot()`, `revision: StateFlow<Long>`,
`onResponse` (DSR/DA replies to send to the host), `encodeKey(key, modifiers)`, `close()`.
`createTerminalEngine(cols, rows, scrollbackLines = 5000)` is an `expect fun`; both actuals return
`JediTermEngine`.

Model: `TerminalColor` (Default / Indexed / Rgb), `CellStyle`, `Cell` (wide chars = width 2 followed by
a width-0 placeholder), `TerminalSnapshot` (full visible grid + cursor, title, scrollback size,
alternate-screen flag).

Implementation notes (`jvmCommonMain/JediTermEngine.kt`):

* `JediTerminal` + `TerminalTextBuffer` + `JediEmulator` with a headless `TerminalDisplay`.
* Input bytes are decoded with a `CharsetDecoder` (leftover bytes are carried over); the emulator
  is driven by a custom data stream that pushes back an escape sequence cut off by the end of the
  data and retries it when more bytes arrive.
* One lock guards feed/resize/snapshot; snapshot also takes the text buffer lock.
* Key encoding is the pure-Kotlin `XtermKeyEncoder` (commonMain); the engine only tracks DECCKM by
  overriding `JediTerminal.setApplicationArrowKeys`.
* `jvmCommonMain` is an explicit intermediate source set (`create("jvmCommonMain") { dependsOn(commonMain) }`,
  with `androidMain` and `desktopMain` depending on it), the same DSL as `:core:ssh`. The JediTerm
  dependency is declared once there; `expect`/`actual` declarations live in `commonMain` with actuals
  in the leaf source sets. Explicit `dependsOn` disables the default hierarchy template, which
  `kotlin.mpp.applyDefaultHierarchyTemplate=false` in `gradle.properties` states explicitly.
* `jediterm-core` pulls `slf4j-api` transitively; the adapter does not use it. Apps bind
  `slf4j-nop` (`runtimeOnly`) so terminal output (which can contain secrets) never reaches a logger.

## Untrusted output: what is bounded or disabled

The host is treated as hostile. Data flows UTF-8 decoder -> `EscapeSequenceFilter` -> emulator.

| Threat | Mitigation |
| --- | --- |
| `CSI 8;rows;cols t` (huge or drifting size) | Remote resize requests are **ignored** (`RequestOrigin.Remote`); local resizes and the initial size are clamped to `TerminalLimits` (5..1000 columns, 2..500 rows). |
| Unterminated or huge escape sequences (quadratic re-parsing, unbounded memory) | The filter holds unfinished sequences itself and forwards only complete ones. CSI: at most 256 characters and 32 parameters, otherwise dropped. OSC: payload at most 64 KiB (4 KiB for titles 0/1/2), otherwise the whole sequence is dropped and the rest is discarded up to its terminator without being buffered. The emulator retry buffer is additionally capped at 64 KiB (`JediTermEngine.pendingChars` is the test hook). |
| Integer overflow in numeric parameters | Every CSI number is clamped to 65535 by rewriting its digits. |
| DCS, APC, PM, SOS, C1 controls (U+0080..U+009F) | Never forwarded. OSC is forwarded normalised as `ESC ] payload BEL`. Strings end at BEL, `ESC \` or U+009C; `ESC` followed by anything else aborts the string; CAN and SUB abort a sequence. |
| Response floods (`CSI 6n`) and blocking consumers | Responses are queued under the engine lock and delivered to `onResponse` **after** the lock is released (never called while internal locks are held; it must not block). At most 64 KiB of responses are queued per call; the rest is dropped. |
| Hostile window titles | Titles are stripped of C0/C1 controls and bidi overrides (U+202A..202E, U+2066..2069) and truncated to 256 characters. The `CSI 22 t` title stack is capped at 10 entries. Title reports (`CSI 20/21 t`), OSC 52 clipboard, OSC 8 hyperlinks, DCS queries and ENQ answerback are not implemented, so there is no echo-back injection. |
| Grid drift | Supplementary-plane characters (emoji) keep JediTerm's column count: a width-2 cell followed by width-0 placeholders, so cells after them stay aligned with the cursor. |

Responses the engine itself produces are fixed-format only (DSR 5/6, DA1, DA2).

## Keyboard model

Hardware keyboard only (`TerminalView`, `KeyboardInput`, `PlatformKeys`):

* Printable text comes from **typed-character events**, not from raw key-downs. Desktop: AWT
  `KEY_TYPED` (Compose maps it to `KeyEventType.Unknown`; the character is read from the AWT event
  via `awtEventOrNull`). Android: the key's unicode character with Ctrl/Alt/Meta removed from the
  meta state, with `KeyCharacterMap` dead-key combining.
* Key-down is used only for special keys (arrows, F-keys, ...) and for Ctrl/Alt combinations with
  ASCII letters, digits or `@ [ \ ] ^ _ space / ? `` ` ``. Already-translated control codes (`0`,
  `0x1c..0x1f`) are accepted; Ctrl+8 sends 0x7f and Ctrl+backtick sends 0x00.
* Non-characters (`0xFFFF` for Shift/Ctrl/Alt/CapsLock/dead keys, `0xFFFE`, U+FDD0..FDEF, ...) are
  never sent.
* AltGr: Ctrl+Alt (Windows) or AltGraph with a printable character that is not an ASCII letter
  sends that character as plain UTF-8, without modifiers.
* Meta/Cmd-modified keys are never sent (including Cmd+arrows).
* macOS: Option composes characters (it is not Meta); the Option-as-Meta setting is not implemented.

## Renderer

`org.terminalmax.core.terminal.ui.TerminalView` draws on a Compose `Canvas`: measures a monospace
cell, derives cols/rows from the size (calls `engine.resize` and `onSizeChanged`), redraws on
`engine.revision` (read inside the Canvas draw scope, so output redraws without recomposition),
backgrounds as rects, text per run of equal style (non-ASCII cells are laid out one by one to keep
the grid), cursor as a cursor-coloured cell with the glyph redrawn in the background colour (outline
when unfocused), hardware keyboard via `onPreviewKeyEvent` (Escape consumed), focus on tap.
`TerminalPalette` holds xterm-like colours and computes the 256-colour cube. Ligatures are disabled
(`fontFeatureSettings = "liga 0, calt 0"`). Bold-as-bright brightens the foreground colour before
inverse swaps fg and bg, as xterm does.

Caches: the resolved-style cache is cleared above 1024 entries; each screen row keeps its backgrounds
and text layouts and is rebuilt only when that row's cells changed (compared by equality). Text runs
are at most 32 columns so a fractional font advance cannot drift far from the grid.

## Not covered by this spike

* Soft keyboard / IME input on Android (hardware keys only); some keyboards and ChromeOS deliver
  characters only through the input method's `commitText`, which needs an input connection. Desktop
  IME composition (CJK) is not handled either. Android Right-Alt as AltGr is not distinguished.
* Selection, copy/paste, bracketed-paste sending, hyperlinks.
* Combining marks: NFC normalisation only happens inside one write chunk, and a lone mark gets its
  own cell; marks split across feeds are not merged.
* Scrollback viewing (scroll gestures / wheel); the snapshot exposes only the live screen and the
  scrollback size.
* Mouse reporting, cursor blink/shape, bell, strikethrough (JediTerm has no attribute), hidden text.
* Sixel / images.
* Performance beyond the per-row render cache: `snapshot()` still copies the whole screen per change
  (no damage tracking from JediTerm's `linesChanged`), so every `Cell` is rebuilt on each redraw even
  though unchanged rows skip text layout.
* A bundled monospace font (box-drawing coverage); `FontFamily.Monospace` falls back differently per OS.
* Numpad application-keypad mode (DECKPAM) and the shortcut scheme for Ctrl+Shift+letter.
* `material3` is still `api` of this module because the shared compose convention plugin applies it to
  every compose module.

## Tests

`commonTest`: key encoder, palette, `EscapeSequenceFilter`, `TitleSanitizer`, `KeyboardInput` (non-characters,
AltGr, translated control codes). `desktopTest`: engine behaviour (colours, cursor, split UTF-8 and
escape sequences, wide chars, resize, alternate screen, DSR, scrollback, title, DECCKM) and
`HostileInputTest` (remote resize, 1 MiB unterminated OSC, 100 000 parameters, huge numbers,
invalid UTF-8, emoji alignment, DSR flood with a blocking callback, title sanitising).
