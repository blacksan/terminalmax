# TerminalMax

A free and open-source SSH terminal for **Android, macOS (Apple silicon) and Windows (x64)**, built with
Kotlin Multiplatform and Compose Multiplatform. Planned features: SSH over a built-in userspace WireGuard
tunnel (no VPN permission, no administrator rights), and an end-to-end encrypted vault of hosts, keys and
snippets that syncs between your devices over WebDAV.

> **Pre-alpha: do not store real credentials yet.**
> This is early, unaudited software. There is no usable user interface, nothing has been tested on a
> physical device, the cryptographic and sync designs have not had an independent security review, and
> file formats may still change incompatibly. Do not put real passwords, private keys or WireGuard
> profiles into it, and do not rely on it for anything. See [SECURITY.md](SECURITY.md).

## What works today

Everything below is exercised by CI (see [How CI builds](#how-ci-builds)); none of it has a real user
interface yet.

* **Builds** of the Android debug and R8-minified release APK, the macOS arm64 DMG and the Windows x64 MSI.
  The packaged desktop apps are launched in CI with `--self-test` to prove that they can load JNA and
  the native bridge.
* **Userspace WireGuard bridge** (`native/wgbridge`): wireguard-go on a gVisor netstack, loaded through
  JNI on Android and JNA on the desktop. No TUN device, no VPN service.
* **SSH over the tunnel, end to end**: an SSH session through the token-protected loopback forwarder and
  the userspace tunnel to an `sshd` behind a real kernel WireGuard peer (CI job `e2e-tunnel`).
* **Terminal engine**: JediTerm core behind an interface, with a shared Compose canvas renderer (spike).
* **Encrypted vault** and **WebDAV sync** libraries with unit and property-style tests. Their formats and
  merge rules are still being hardened.

## What does not exist yet

* A real user interface. The apps show a proof screen only.
* On-device testing (Android hardware, a real Mac, a real Windows machine).
* Signed or notarised release builds. CI artifacts are unsigned test builds of every push.
* A security audit, a vulnerability track record or supported releases.

## Modules

| Module | Purpose |
| --- | --- |
| [`:androidApp`](androidApp) | Android application (`org.terminalmax.app`), ships `libwgbridge.so` for arm64-v8a and x86_64 |
| [`:desktopApp`](desktopApp) | Compose Desktop application (DMG / MSI packaging, `--self-test` launch mode) |
| [`:core:model`](core/model) | Shared domain models |
| [`:core:designsystem`](core/designsystem) | Shared Material 3 Expressive theme |
| [`:core:ssh`](core/ssh/README.md) | SSH transport (sshj), host-key verification, optional loopback preamble for the tunnel |
| [`:core:wireguard`](core/wireguard/README.md) | Kotlin binding of the WireGuard bridge (JNI on Android, JNA on desktop) |
| [`:core:terminal`](core/terminal/README.md) | Terminal engine (JediTerm core) and renderer spike |
| [`:core:vault`](core/vault/README.md) | Encrypted vault: record model, merge, on-disk format ([FORMAT.md](core/vault/FORMAT.md)) |
| [`:core:sync`](core/sync/README.md) | WebDAV synchronisation of the vault file |
| [`:feature:proof`](feature/proof) | Proof screen |
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
