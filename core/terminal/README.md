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
maven {
    url = uri("https://packages.jetbrains.team/maven/p/ij/intellij-dependencies")
    content { includeGroup("org.jetbrains.jediterm") }
}
```

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
* `jvmCommonMain` is a source directory added to both `androidMain` and `desktopMain` rather than a
  true intermediate source set: with the AGP KMP library plugin the hierarchy-template group does
  not attach `androidMain` (KT-80409).

## Renderer

`org.terminalmax.core.terminal.ui.TerminalView` draws on a Compose `Canvas`: measures a monospace
cell, derives cols/rows from the size (calls `engine.resize` and `onSizeChanged`), redraws on
`engine.revision`, backgrounds as rects, text per run of equal style (non-ASCII cells are drawn one
by one to keep the grid), block cursor (outline when unfocused), hardware keyboard via
`onPreviewKeyEvent` (Escape consumed), focus on tap. `TerminalPalette` holds xterm-like colours and
computes the 256-colour cube.

## Not covered by this spike

* Soft keyboard / IME input on Android (hardware keys only).
* Selection, copy/paste, bracketed-paste sending, hyperlinks.
* Scrollback viewing (scroll gestures / wheel); the snapshot exposes only the live screen and the
  scrollback size.
* Mouse reporting, cursor blink/shape, bell, strikethrough (JediTerm has no attribute), hidden text.
* Sixel / images.
* Non-BMP glyph width (surrogate pairs are kept as one cell without width handling).
* Performance tuning (snapshot copies the whole screen per change; no damage tracking).

## Tests

`commonTest`: key encoder, palette. `desktopTest`: engine behaviour (colours, cursor, split UTF-8 and
escape sequences, wide chars, resize, alternate screen, DSR, scrollback, title, DECCKM).
