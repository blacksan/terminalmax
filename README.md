# TerminalMax

A free and open-source SSH terminal for **Android, macOS (Apple silicon) and Windows (x64)**, built with
Kotlin Multiplatform and Compose Multiplatform. It connects over SSH, optionally through a built-in
userspace WireGuard tunnel (no VPN permission, no administrator rights), and keeps hosts, keys and WireGuard
profiles in an end-to-end encrypted vault that syncs between your devices over WebDAV.

> **Pre-alpha: do not store real credentials yet.**
> This is early, unaudited software. The app is new and has only been built and unit-tested in CI, nothing
> has been tested on a physical device, the cryptographic and sync designs have not had an independent security review, and
> file formats may still change incompatibly. Do not put real passwords, private keys or WireGuard
> profiles into it, and do not rely on it for anything. See [SECURITY.md](SECURITY.md).

## What the app can do now

See the [user guide](docs/USER_GUIDE.md) for a walk-through.

* **Vault**: create a vault with a password, join an existing one from a WebDAV server (after comparing its
  fingerprint and revision with another device), unlock, lock. On Android the vault locks itself after
  5 minutes in the background when no session is open. Quick unlock (fingerprint, system keychain) is **not**
  part of this release.
* **Hosts**: list with search, add / edit / delete. Password or pasted private key (with optional passphrase),
  optional WireGuard profile, algorithm profile Modern (default) or Legacy (with a warning), optional RouterOS
  console options such as `+ct80w` appended to the user name.
* **WireGuard profiles**: import a wg-quick configuration by pasting it or choosing a file. It is validated
  before it is stored and the private key is never shown again.
* **Terminal sessions**: tap a host to connect (through its tunnel if it has one). Host keys are checked
  against the vault: unknown keys ask you to trust them, changed keys show a warning. Several sessions at
  once (Sessions tab, tabs on the desktop). Reconnect after a failure. On Android: extra-keys row (Esc, Tab,
  sticky Ctrl and Alt, arrows, Home, End, PgUp, PgDn, `|`, `-`, `/`), soft-keyboard input and a foreground
  service with a notification, a wake lock and a tunnel re-handshake on network changes while sessions are open.
* **Sync**: WebDAV address and credentials (stored in the vault), test server, sync now, optional automatic
  sync (off by default), and dialogs for every outcome that needs a decision (large remote change, rollback,
  re-key, replace the server copy, ...).
* **Settings**: theme, terminal font size, about / licence / third-party notices, backup export.
* **Builds** of the Android debug and R8-minified release APK, the macOS arm64 DMG and the Windows x64 MSI,
  all produced by CI (see [How CI builds](#how-ci-builds)). The packaged desktop apps are launched in CI with
  `--self-test` to prove that they can load JNA and the native bridge.
* **Userspace WireGuard bridge** (`native/wgbridge`): wireguard-go on a gVisor netstack, loaded through JNI on
  Android and JNA on the desktop, and **SSH over the tunnel, end to end** against a kernel WireGuard peer (CI
  job `e2e-tunnel`).

## Installing a build

CI builds are **unsigned test builds**. Download them from the Actions run of a commit (artifact names
`terminalmax-debug-apk`, `terminalmax-macos-arm64-dmg`, `terminalmax-windows-x64-msi`), or from a
pre-release when a version tag was published.

* **Android** (8.0 or newer, arm64 or x86_64): copy the APK to the phone and open it. Allow "install unknown
  apps" for your file manager or browser when asked. It is signed with a debug key, so it cannot update a
  build signed by anyone else.
* **macOS** (Apple silicon): open the DMG and drag TerminalMax to Applications. The app is not notarised, so
  the first start is blocked: right-click the app and choose Open, or allow it in System Settings, Privacy &
  Security.
* **Windows** (x64): run the MSI. SmartScreen may warn because the installer is unsigned: choose "More info",
  then "Run anyway".

## What is missing

* On-device testing (Android hardware, a real Mac, a real Windows machine). Real routers and WebDAV servers
  have not been tried either.
* Quick unlock with biometrics or the system keychain.
* A password-change screen (the library supports it; the app only handles the sync outcomes of a change made
  elsewhere), snippets, a vault history / restore screen, and import of OpenSSH `known_hosts` or key files.
* Signed or notarised release builds, a security audit and supported releases.

## Deliberate deviations

* **Navigation** is a small typed back stack of `Screen` keys in common code (`Navigator`), not Navigation 3,
  to keep the first release low-risk. Android predictive back goes through the platform `BackHandler`; the
  desktop uses Esc.
* **Dependency injection** is a plain constructor-injected `AppContainer` per platform process, not Hilt
  (Hilt is Android-only).
* The state holders are plain classes exposing `StateFlow` (collected with `collectAsStateWithLifecycle`)
  with an injected `CoroutineScope`, not `androidx.lifecycle.ViewModel` subclasses: the vault session must
  outlive activities and windows, and this keeps them unit-testable without a main dispatcher.
* `:feature:app` compiles its JVM-only sources (`src/jvmShared`) into both the Android and the desktop target
  because a consumer's intermediate source set cannot see the JVM-only declarations of `:core:sync` and
  `:core:ssh`.

## Modules

| Module | Purpose |
| --- | --- |
| [`:androidApp`](androidApp) | Android application (`org.terminalmax.app`), ships `libwgbridge.so` for arm64-v8a and x86_64 |
| [`:desktopApp`](desktopApp) | Compose Desktop application (DMG / MSI packaging, `--self-test` launch mode) |
| [`:core:model`](core/model) | Shared domain models |
| [`:core:designsystem`](core/designsystem) | Shared Material 3 Expressive theme |
| [`:core:ssh`](core/ssh/README.md) | SSH transport (sshj), host-key verification, optional loopback preamble for the tunnel |
| [`:core:wireguard`](core/wireguard/README.md) | Kotlin binding of the WireGuard bridge (JNI on Android, JNA on desktop) |
| [`:core:terminal`](core/terminal/README.md) | Terminal engine (JediTerm core) and renderer |
| [`:core:vault`](core/vault/README.md) | Encrypted vault: record model, merge, on-disk format ([FORMAT.md](core/vault/FORMAT.md)) |
| [`:core:sync`](core/sync/README.md) | WebDAV synchronisation of the vault file |
| [`:feature:app`](feature/app) | The app: screens, state holders and the platform-service interface |
| [`:integration-tests`](integration-tests) | End-to-end tunnel test against a real WireGuard peer |
| [`native/wgbridge`](native/wgbridge/README.md) | Go source of the native bridge (wireguard-go + gVisor netstack) |
| `build-logic` | Convention plugins |

## Security model in brief

Details, limits and known gaps are in the module READMEs; this is a summary, not a guarantee.

* **Vault** ([`core/vault`](core/vault/README.md), [format](core/vault/FORMAT.md)): one encrypted file,
  authenticated encryption, a password slot hardened with Argon2id and optional per-device public-key
  slots; key rotation when a password changes or a slot is removed.
* **Sync** ([`core/sync`](core/sync/README.md)): the WebDAV server only ever sees the encrypted file. The
  client uses conditional requests, remembers the newest state it has seen to detect rollback, and treats
  the server as untrusted.
* **WireGuard** ([`core/wireguard`](core/wireguard/README.md), [`native/wgbridge`](native/wgbridge/README.md)):
  runs inside the app process; keys live in process memory while a tunnel is up. The desktop app loads
  the bridge only from its own resources directory, pins JNA's native stub to the bundled copy and checks
  after loading that it is the one in use.
* **SSH** ([`core/ssh`](core/ssh/README.md)): host keys must be verified by the app; modern algorithms by
  default, with legacy crypto flagged to the user.
* **Not audited.** No claim here has been independently reviewed. Report problems privately as described
  in [SECURITY.md](SECURITY.md).

## Building

Requires JDK 21 (and the Android SDK for the Android app). The native bridge is built by CI and is never
committed; see [`native/wgbridge`](native/wgbridge/README.md) for the Go build scripts.

* Android debug APK: `./gradlew :androidApp:assembleDebug`
* Desktop run: `./gradlew :desktopApp:run`
* Desktop installer for the current OS: `./gradlew :desktopApp:packageDistributionForCurrentOS`
* Packaged-app smoke test: `<launcher> --self-test=<result file>` (prints `SELFTEST OK` and exits 0 when
  the bridge and JNA load from the app's own resources)
* Tests: `./gradlew desktopTest`

## How CI builds

GitHub Actions ([`.github/workflows/ci.yml`](.github/workflows/ci.yml), [`native.yml`](.github/workflows/native.yml)):

* **android**: builds `libwgbridge.so` with the NDK, builds the debug APK and the minified release APK,
  runs the desktop unit tests, and asserts that both APKs contain the bridge and that R8 kept the JNI names.
* **desktop-macos / desktop-windows**: builds the bridge, packages the DMG / MSI, asserts that the final
  installer contains the bridge, the JNA stub and the licence notices, then runs the packaged app with
  `--self-test`.
* **e2e-tunnel**: SSH through the userspace tunnel to an `sshd` behind a kernel WireGuard interface.
* **native**: Go vet and tests (including the race detector) for the bridge, with `go.sum` verified.

Third-party actions are pinned to commit SHAs. Artifacts uploaded by CI are unsigned and are not releases.

## Licence

GPL-3.0-or-later. See [LICENSE](LICENSE). Third-party components and their notices are listed in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md); contributions are accepted under the same licence, see
[CONTRIBUTING.md](CONTRIBUTING.md).
