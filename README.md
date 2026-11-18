# TerminalMax

A free and open-source (GPL-3.0-or-later) SSH terminal for Android, macOS (arm64) and Windows (x64),
built with Kotlin Multiplatform and Compose Multiplatform.

**Status: Phase 0 proof.** The project currently only proves that the shared Material 3 Expressive
theme and the build/CI pipeline work on all targets. There is no SSH functionality yet.

## Modules

| Module | Purpose |
| --- | --- |
| `:androidApp` | Android application (`org.terminalmax.app`) |
| `:desktopApp` | Compose Desktop application (dmg / msi packaging) |
| `:core:model` | Shared domain models |
| `:core:designsystem` | Shared Material 3 Expressive theme (colour, shape, type) |
| `:feature:proof` | Phase 0 proof screen |
| `build-logic` | Convention plugins (`terminalmax.kmp.library`, `terminalmax.kmp.compose`, `terminalmax.android.application`) |

## Building

Requires JDK 21 (Android SDK for the Android app).

- Android debug APK: `./gradlew :androidApp:assembleDebug`
- Desktop run: `./gradlew :desktopApp:run`
- Desktop installer for the current OS: `./gradlew :desktopApp:packageDistributionForCurrentOS`
- Tests: `./gradlew desktopTest`

## CI

GitHub Actions (`.github/workflows/ci.yml`) builds the debug APK and runs tests on Linux, packages a
dmg on macOS (arm64) and an msi on Windows, and uploads each as a workflow artifact.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
