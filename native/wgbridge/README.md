# wgbridge

Userspace WireGuard for TerminalMax. It runs entirely inside the app process
using [wireguard-go](https://git.zx2c4.com/wireguard-go) with its gVisor
netstack TUN: no TUN device, no VPN service, no administrator rights.

For each SSH session the host app asks for a *forwarder*: a TCP listener on
`127.0.0.1:<random port>` that accepts exactly one connection, then closes
the listener, dials the target through the tunnel and copies bytes both ways
until either side closes. The SSH library connects to `127.0.0.1:<port>`.

## Layout

| Path | Purpose |
| --- | --- |
| `wgconf/` | wg-quick `.conf` parser, UAPI generator, endpoint resolver, stats parser (stdlib only) |
| `forward/` | one-connection loopback forwarder behind a `Dialer` interface (stdlib only) |
| `tunnel/` | wireguard-go device + netstack, `Start/OpenForward/Stats/Rebind/Close` |
| `cmd/libwgbridge/` | C ABI (cgo, `-buildmode=c-shared`) and Android JNI glue |
| `build-android.sh`, `build-desktop.sh` | release builds |

`go.sum` is not committed yet: run `go mod tidy` (CI does, and uploads the
resulting `go.mod`/`go.sum` as an artifact).

## C ABI

All functions use `int` handles and C strings; no Go pointers cross the
boundary and nothing is retained after a call returns. The handle table is
thread-safe. Every string that crosses the ABI (error messages, stats JSON,
version) is printable ASCII (0x20..0x7e): other bytes are replaced by `?`.
Config text passed to `wgbStart` is read as bytes (UTF-8 is fine in
comments) and must be shorter than 1 MiB.

The prototypes below are exactly what cgo generates (`char *`, not
`const char *`; the library never writes through `confText`/`target`):

```c
int   wgbStart(char *confText, char *errBuf, int errLen);
int   wgbOpenForward(int handle, char *target, unsigned char *tokenOut,
                     char *errBuf, int errLen);
int   wgbStats(int handle, char *buf, int length, char *errBuf, int errLen);
int   wgbRebind(int handle);
void  wgbStop(int handle);
int   wgbLastError(char *buf, int length);
char *wgbVersion(void);   /* static; do not free */
```

* `wgbStart` parses a wg-quick style config and starts a tunnel. Returns a
  handle > 0, or a negative code. The message is written to `errBuf` (may be
  NULL) and is also available through `wgbLastError`. Zero your copy of
  `confText` after the call.
* `wgbOpenForward` takes `host:port` and returns the loopback port. `target`
  must be an IP literal unless the profile has `DNS =` servers (otherwise it
  fails with a clear error). `tokenOut` must point to **32 writable bytes**
  (NULL is rejected): on success they receive a random per-forward token
  that the client must send as the **first 32 bytes** on the loopback
  connection, before any SSH data. Open the forward immediately before
  connecting: it expires after 5 s without a client, and the client has 5 s
  to send the token. On failure the message goes to `errBuf` (may be NULL)
  and `wgbLastError`.
* `wgbStats` writes
  `{"last_handshake_unix_ms":N,"rx_bytes":N,"tx_bytes":N}` plus, once a
  forwarder has failed, `,"last_forward_error":"..."` (ASCII, at most 120
  characters) and, once wireguard-go has logged an error,
  `,"last_device_error":"..."` (ASCII, at most 256 characters).
  `last_handshake_unix_ms` is 0 if no handshake has completed. Use a buffer
  of at least 768 bytes. **Poll stats sparingly** (at most every 5-10 s and
  only while the UI is visible): see the key-handling note below. Per-call errors go to `errBuf`.
* `wgbRebind` closes and reopens the tunnel's UDP socket (device down/up) so
  WireGuard re-handshakes immediately. Returns 0 or a negative code.
* `wgbStop` closes forwarders, then the device. Unknown handles are ignored.
* `wgbLastError` is process-global (last error from any call); prefer the
  per-call `errBuf`.

Error codes: `-1` bad config, `-2` tunnel start failed, `-3` bad handle,
`-4` forward/stats/rebind failure, `-5` buffer too small, `-6` NULL/invalid
argument.

**Go shared libraries must never be unloaded.** Do not call `dlclose` or
`FreeLibrary` on `libwgbridge`/`wgbridge.dll`: the Go runtime's threads and
timers keep running and unloading crashes the process. Load once, keep it
loaded until exit.

### Android JNI

`cmd/libwgbridge/jni_android.c` (compiled only for `GOOS=android`) provides
the natives for Kotlin class `org.terminalmax.core.wireguard.WgBridgeNative`.
Only the `arm64-v8a` and `x86_64` ABIs are built; there is no 32-bit
(`armeabi-v7a`, `x86`) library, so the app must filter its ABIs accordingly.

```kotlin
package org.terminalmax.core.wireguard

object WgBridgeNative {
    init { System.loadLibrary("wgbridge") }
    @Throws(java.io.IOException::class)
    external fun nativeStart(config: ByteArray): Int      // handle > 0; throws on failure
    external fun nativeLastError(): String                // process-global message of the last failure
    @Throws(java.io.IOException::class)
    external fun nativeOpenForward(handle: Int, target: String, tokenOut: ByteArray): Int // port; tokenOut.size must be 32
    @Throws(java.io.IOException::class)
    external fun nativeStats(handle: Int): String         // JSON
    external fun nativeRebind(handle: Int): Int           // 0 or negative
    external fun nativeStop(handle: Int)
}
```

* `nativeStart` takes the config as a `ByteArray` (ASCII/UTF-8) so that no
  immutable `String` copy of the keys is created. The native side copies it
  with `GetByteArrayRegion` into one malloc buffer, which the bridge parses
  in place and wipes before returning. It does **not** touch your array:
  **the caller must `fill(0)` the config `ByteArray` after `nativeStart`
  returns** (in a `finally`). On failure it throws `java.io.IOException` with
  the per-call message (a NULL array also throws); it no longer depends on
  `nativeLastError`.
* `nativeOpenForward` and `nativeStats` throw `java.io.IOException` with the
  per-call message on failure (`nativeOpenForward` also returns the negative
  code if the exception is swallowed). A `tokenOut` that is not exactly 32
  bytes throws. The native token copy is zeroed after being copied into the
  array; the caller should zero its array after use.
* `target` goes through `GetStringUTFChars` (modified UTF-8); use ASCII.

## Building

* Tests: `go mod tidy && go vet ./... && go test ./wgconf/ ./forward/ ./cmd/... -race -count=1`
  and `go test ./tunnel/ -count=1 -timeout 180s -v` (the two-device
  integration test runs without `-race`).
* Android (needs `ANDROID_NDK_HOME`): `./build-android.sh` ->
  `out/android/{arm64-v8a,x86_64}/libwgbridge.so`, API 26, 16 KB page
  aligned; the script fails if any LOAD segment is aligned below 2**14.
* macOS: `./build-desktop.sh` -> `out/macos-arm64/libwgbridge.dylib`,
  ad-hoc signed. Windows (Git Bash, mingw gcc): `out/windows-x64/wgbridge.dll`.

## Device sleep on Android

The Go runtime's timers stop while the CPU is suspended: this build does not
apply wireguard-android's "goruntime-boottime-over-monotonic" patch, which
makes the runtime use `CLOCK_BOOTTIME`. Without it, keepalives and rekey
timers do not advance during deep sleep and a tunnel can look alive but be
dead after wake-up. Until that patch is vendored (tracked TODO), the host app
must:

* hold a `PARTIAL_WAKE_LOCK` for as long as SSH sessions are open, and
* call `nativeRebind` on every network change (`ConnectivityManager` network
  callback) and when the screen turns on / the device wakes.

## Security notes

* The forwarder listens on `127.0.0.1` only, on a random port, and accepts
  exactly one connection; the listener is closed right after `accept`
  (and on timeout or cancellation). On Windows the socket is created with
  `SO_EXCLUSIVEADDRUSE`, so another process cannot bind the same port.
* Any local process can still *connect* to the loopback port during the
  accept window (5 s), so each forward has a random 32-byte token
  (`crypto/rand`) that the client must send first; it is compared in
  constant time before the target is dialled. A process that guesses wrong
  or stays silent never gets a byte into the tunnel, but it can still use up
  the single accept slot, so the **residual risk is denial of service**:
  whoever connects first consumes the single slot, the legitimate client then
  gets connection refused/reset, and the authentication failure surfaces
  within 5 s as `forward: client failed authentication` (also in stats
  `last_forward_error`). No bytes reach the tunnel. The caller simply calls
  OpenForward again for a fresh port and token.
  The token only travels over loopback and in your process memory; do not
  log it. **SSH host-key verification remains mandatory**: the token
  protects the tunnel entry point, not the SSH session.
* Key handling, honestly: keys never appear in error messages (parser
  errors redact any value with 16 or more base64/base64url/hex characters,
  resolver text is never echoed), return values or logs, and wireguard-go is
  configured with a logger that discards everything except errors (kept in
  memory, surfaced ASCII-sanitised as `last_device_error`). **Keys remain in
  process memory for the tunnel's lifetime**: wireguard-go keeps the private
  and preshared keys, and it keeps unzeroed copies of the UAPI lines passed to
  `IpcSet`. The bridge reduces what it controls: it parses the config in place
  over the caller's buffer (no Go copy, `Parse` retains no substrings),
  builds the UAPI text in a pre-sized buffer that it zeroes after use, zeroes
  `wgconf.Config` keys (also on parse errors) and its own C buffer, and parses
  stats from a stream that never stores key lines. But every stats call goes
  through `IpcGet`, and wireguard-go serialises the private and preshared keys
  into an internal pooled buffer each time, so poll stats sparingly (at most
  every 5-10 s and only while the UI is visible). Go strings and slices
  cannot be reliably erased, and the Kotlin caller must zero its own
  `ByteArray`. Store keys in the platform keystore and treat a memory dump of
  the app as exposing them.
  TODO: reading rx/tx through a wrapping `conn.Bind` (counting bytes at the
  UDP socket) would avoid `IpcGet` entirely.
* wg-quick script hooks (`PreUp`, `PostUp`, ...) are rejected, not run.
* Endpoint host names are resolved with the system resolver outside the
  tunnel; use IP endpoints if that leaks too much.

## Licenses

This code is GPL-3.0-or-later. It links wireguard-go (MIT, WireGuard LLC)
and gVisor (Apache-2.0), plus golang.org/x/{crypto,net,sys} (BSD-3-Clause).
Ship their license texts with binary distributions. "WireGuard" is a
registered trademark of Jason A. Donenfeld.
