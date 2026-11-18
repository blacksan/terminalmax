# :core:wireguard

Kotlin binding of the native WireGuard bridge (`native/wgbridge`, wireguard-go with a gVisor
netstack: no TUN device, no VPN service, no administrator rights). The public API lives in
`commonMain`; the bridge is reached through JNI on Android and through
[JNA](https://github.com/java-native-access/jna) (5.19.1) on the desktop.

## API

```kotlin
interface WireGuardBackend {
    fun version(): String
    fun start(configText: ByteArray): WireGuardTunnel   // consumes and zero-fills configText
}

interface WireGuardTunnel : AutoCloseable {
    fun openForward(targetIp: String, port: Int): LoopbackForward
    fun stats(): TunnelStats
    fun rebind()
    override fun close()                                // idempotent
}

class LoopbackForward(val port: Int, token: ByteArray)  // 32-byte token, copied, redacted toString
data class TunnelStats(lastHandshakeEpochSeconds: Long?, rxBytes: Long, txBytes: Long,
                       lastForwardError: String?, lastDeviceError: String?)
class WireGuardException(message: String, cause: Throwable? = null) : Exception

expect fun createWireGuardBackend(): WireGuardBackend
```

Typical use with `:core:ssh`:

```kotlin
val backend = createWireGuardBackend()                  // once per process
val tunnel = backend.start(configBytes)                 // configBytes is zero-filled
val forward = tunnel.openForward("10.0.0.1", 22)        // open right before connecting
ssh.connect(target, auth, verifier, via = LoopbackPreamble(forward.port, forward.token))
```

Rules:

* All methods are **blocking**; call them off the main thread (`Dispatchers.IO`).
* `start` zero-fills the array it is given, also on failure. The bridge keeps keys in process
  memory for the tunnel's lifetime (see `native/wgbridge/README.md`).
* `openForward` needs an IP literal (no brackets) and throws `IllegalArgumentException` for a bad
  literal or port. Open the forward immediately before connecting: it expires after 5 s without a
  client. Wipe the token copies you read. `close()` wipes the stored token of every forward the
  tunnel handed out (and the oldest ones once more than 64 are outstanding).
* On the desktop the forwarder token travels through a JNA `Memory` block that is zeroed after the
  copy; the config likewise.
* **Poll `stats()` sparingly**: at most every 5 s and only while the UI is visible; every call
  makes wireguard-go serialise its keys into an internal buffer.
* `close()` is idempotent; using a closed tunnel throws `WireGuardException`.
* The native library is loaded once per process and **never unloaded** (Go runtime threads keep
  running).

## Library loading

**Android** (`androidMain`): `WgBridgeNative` calls `System.loadLibrary("wgbridge")`; its
`external` functions match `native/wgbridge/cmd/libwgbridge/jni_android.c` exactly. The app ships
`libwgbridge.so` for `arm64-v8a` and `x86_64` only (`abiFilters` in `:androidApp`). A consumer
R8 rule keeps the native method names.

**Desktop** (`desktopMain`, JNA) has exactly one production lookup and no fall-through:

1. The bridge is loaded **only** from `<compose.application.resources.dir>/libwgbridge.dylib |
   wgbridge.dll | libwgbridge.so` (by OS). The path is resolved with `toRealPath()` and must be a
   regular file (not a symbolic link) inside the real resources directory; otherwise
   `createWireGuardBackend()` throws a `WireGuardException` ("bundled native library is missing for
   this platform"). The default JNA search (`Native.load("wgbridge")`, `jna.library.path`, the OS
   library path, `~/Library/Frameworks`, `PATH`, the current directory) is never used.
2. JNA's own native stub (`jnidispatch`) is shipped next to the bridge and pinned before any JNA
   class is initialised: `jna.boot.library.path=<resources dir>`, `jna.nosys=true`,
   `jna.nounpack=true`, `jna.noclasspath=true`. Nothing is extracted to a temp directory and no
   other copy can be found; if the bundled stub is missing or cannot be loaded, loading fails.
   `:desktopApp` copies the stub (`libjnidispatch.jnilib` for macOS arm64, `jnidispatch.dll` for
   Windows x64) out of the very `jna` jar the app runs with (task `bundleJnaDispatch`).
   **The backend must be the first JNA user in the process** (the app has no other).
3. `-Dterminalmax.wgbridge.path=<absolute file>` is honoured **only** together with
   `-Dterminalmax.dev=true` (unit/integration tests, the e2e CI job, local development). Without
   the flag the property is an error, not ignored. In dev mode, when no bundled stub exists, JNA may
   extract its stub, but `jna.tmpdir` is pointed at a private owner-only directory
   (`%LOCALAPPDATA%\TerminalMax\jna`, `~/Library/Caches/terminalmax/jna`, `$XDG_CACHE_HOME` or
   `~/.cache/terminalmax/jna` with mode `0700`) unless you set `jna.tmpdir` yourself.

Not done: a build-time SHA-256 of the bridge that the loader verifies, and Developer ID signing of
the bundled dylibs (the bridge is ad-hoc signed by `native/wgbridge/build-desktop.sh`; the JNA stub
keeps the signature of the upstream jar).

## Bundling (libraries are built by CI, never committed)

* Android: `native/wgbridge/build-android.sh` output is copied to
  `androidApp/src/main/jniLibs/{arm64-v8a,x86_64}/libwgbridge.so` before Gradle runs; CI asserts
  with `unzip -l` that the debug and release APKs contain them, and that the JNI class and its
  native method names survived R8.
* Desktop: `desktopApp/resources/macos-arm64/{libwgbridge.dylib,libjnidispatch.jnilib}` and
  `desktopApp/resources/windows-x64/{wgbridge.dll,jnidispatch.dll}` (`appResourcesRootDir` of the
  Compose distribution; the per-OS-and-arch folders are `<os>-<arch>`; their files end up directly
  in `$APPDIR/resources`). CI builds the bridge; Gradle adds the JNA stub. CI then mounts the final
  `.dmg` and runs `msiexec /a` on the final `.msi` and asserts that both libraries are inside.
  `modules("jdk.unsupported", "java.logging")` keeps what JNA needs in the jlink runtime.

## Duties of the app layer on Android

The Go runtime's timers stop while the CPU is suspended (the bridge does not carry the
`CLOCK_BOOTTIME` patch). The app must:

* hold a `PARTIAL_WAKE_LOCK` for as long as SSH sessions are open, and
* call `WireGuardTunnel.rebind()` on every network change (`ConnectivityManager` callback) and
  when the screen turns on / the device wakes.

## Tests

`desktopTest` covers stats JSON parsing, argument validation, zero-filling, token wiping and close
semantics with a fake bridge, plus the loader rules (no fall-through to `jna.library.path`, symbolic
links and files outside the resources directory are rejected, the override needs the dev flag).
Loading the real library is exercised by `:integration-tests`.
