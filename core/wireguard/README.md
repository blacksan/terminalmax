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
* `openForward` needs an IP literal (no brackets). Open the forward immediately before
  connecting: it expires after 5 s without a client. Wipe the token copies you read.
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

**Desktop** (`desktopMain`, JNA), first match wins:

1. system property `terminalmax.wgbridge.path`: absolute path of an existing file (an invalid
   value is an error, not a fall-through);
2. `<compose.application.resources.dir>/libwgbridge.dylib | wgbridge.dll | libwgbridge.so`
   (by OS) when that file exists;
3. the default JNA search for `wgbridge` (`jna.library.path`, the OS library path).

## Bundling (libraries are built by CI, never committed)

* Android: `native/wgbridge/build-android.sh` output is copied to
  `androidApp/src/main/jniLibs/{arm64-v8a,x86_64}/libwgbridge.so` before Gradle runs; CI asserts
  with `unzip -l` that the debug and release APKs contain them.
* Desktop: `desktopApp/resources/macos-arm64/libwgbridge.dylib` and
  `desktopApp/resources/windows-x64/wgbridge.dll` (`appResourcesRootDir` of the Compose
  distribution; the per-OS-and-arch folders are `<os>-<arch>`). `modules("jdk.unsupported",
  "java.logging")` keeps what JNA needs in the jlink runtime.

## Duties of the app layer on Android

The Go runtime's timers stop while the CPU is suspended (the bridge does not carry the
`CLOCK_BOOTTIME` patch). The app must:

* hold a `PARTIAL_WAKE_LOCK` for as long as SSH sessions are open, and
* call `WireGuardTunnel.rebind()` on every network change (`ConnectivityManager` callback) and
  when the screen turns on / the device wakes.

## Tests

`desktopTest` covers stats JSON parsing, argument validation, zero-filling and close semantics
with a fake bridge. Loading the real library is exercised by `:integration-tests`.
