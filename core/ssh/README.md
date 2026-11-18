# :core:ssh

SSH transport for TerminalMax. The public API (`SshTransport`, `SshSession`, `SshShell`,
`HostKeyVerifier`, `SshException`, ...) lives in `commonMain` and uses no JVM types. The only
implementation, `SshjTransport`, is in the `jvmCommonMain` source set shared by the Android and
desktop targets and is backed by [sshj](https://github.com/hierynomus/sshj) 0.41.2.

## API

```kotlin
interface SshTransport {
    suspend fun connect(
        target: SshTarget,
        auth: SshAuth,
        hostKeyVerifier: HostKeyVerifier,
        via: LoopbackPreamble? = null,
        options: SshConnectOptions = SshConnectOptions(),
    ): SshSession
}

data class SshConnectOptions(
    val connectTimeoutMillis: Int = 15_000,
    val keepAliveSeconds: Int = 15,
    val keepAliveMaxMissed: Int = 3,
    val algorithms: AlgorithmProfile = AlgorithmProfile.Modern,
)

interface SshSession {
    val negotiated: NegotiatedAlgorithms   // kex, hostKey, cipherC2s/S2c, macC2s/S2c
    val usesLegacyCrypto: Boolean          // show a warning badge when true
    suspend fun openShell(pty: PtyRequest = PtyRequest()): SshShell
    suspend fun exec(command: String): ExecResult
    fun close()
}
```

## Algorithm profiles

sshj's own defaults enable weak crypto (DH group1, DSA, RC4, MD5, 3DES, Blowfish, ...) and prefer
it over strong options (`aes128-cbc` before `aes128-ctr`, `hmac-sha1` before `hmac-sha2`). The
defaults are never used: both profiles are explicit lists in preference order (see
`SshAlgorithms.kt`), built once on first use and shared by all connections.

- **`Modern`** (default): curve25519, ECDH and DH group exchange / groups 14-18 with SHA-2;
  ChaCha20-Poly1305, AES-GCM, AES-CTR; HMAC-SHA-2 (encrypt-then-MAC first); Ed25519, ECDSA and
  RSA with SHA-2 host keys. Strict KEX (the Terrapin mitigation) and `ext-info-c` stay enabled.
- **`Legacy`**: `Modern` plus the following, **appended** so they only win when the server
  offers nothing better: `diffie-hellman-group14-sha1`, `-group-exchange-sha1`, `-group1-sha1`;
  `aes256-cbc`, `aes192-cbc`, `aes128-cbc`, `3des-cbc`; `hmac-sha1`; `ssh-rsa` (SHA-1) and
  `ssh-dss` host keys. Never RC4, MD5 or `none`.

**There is no automatic fallback from `Modern` to `Legacy`.** A network attacker can make a
handshake fail with a TCP reset, so falling back automatically would turn into a downgrade
attack. `Legacy` is a per-host choice made by the user (for example for RouterOS 6 era devices).
A `Modern` connection to such a device fails with `SshException.Protocol` ("no common
algorithms"); the UI may then offer to retry with `Legacy` after explaining the risk.
`SshSession.usesLegacyCrypto` is true when anything outside the `Modern` lists was negotiated.

The legacy list is an inference from forum reports, not verified against real RouterOS 6 devices.

## Host keys

`HostKeyVerifier` is a **pure lookup** (`check(host, port, keyType, fingerprintSha256, key)`
returning `Trusted`, `Unknown` or `Mismatch`) because it runs on the SSH reader thread during key
exchange and must not block or prompt. For trust-on-first-use:

1. `connect` fails with `SshException.HostKeyUnknown` (host, port, key type, SHA-256 fingerprint,
   key blob) or `SshException.HostKeyChanged`.
2. The UI shows the fingerprint, the user decides, the key is stored.
3. The UI calls `connect` again.

Details:

- The verifier always receives the real `SshTarget` host and port, never the loopback address.
- `knownKeyTypes(host, port)` (optional, default empty) is passed to sshj so that a host with a
  stored ECDSA key does not look "unknown" just because the server offers Ed25519 first.
- The first accepted key blob is **pinned for the life of the connection**: a later key exchange
  must present the same key (`MessageDigest.isEqual`), otherwise the connection fails with
  `HostKeyChanged`.
- An exception thrown by the verifier fails the connect with `SshException.Protocol`; the
  verifier's exception is the cause.
- There is no accept-all verifier in main code.

`SshException` is sealed: `HostKeyUnknown`, `HostKeyChanged`, `AuthFailed`, `Timeout`,
`Unreachable`, `Protocol`. Cancellation is never an `SshException`; it propagates as
`CancellationException`.

## Cancellation, timeouts, keep-alive

- `connect` is cancellable. Cancelling closes the socket (even while the loopback preamble is
  being written) and the sshj client, which unblocks the handshake; a session that finished
  connecting just as the caller was cancelled is closed. `withTimeout(...) { connect(...) }` is
  therefore a real overall deadline. (A DNS lookup for a host name target is not interruptible.)
- `connectTimeoutMillis` is the TCP connect timeout and the time sshj waits for each protocol
  step (key exchange, each authentication method, channel requests).
- Keep-alive is configured **before** connecting (sshj starts the keep-alive thread during
  `connect` and only if the interval is already positive) and uses `keepalive@openssh.com`, which
  needs an answer. The connection is declared dead after `keepAliveMaxMissed` unanswered requests,
  roughly `keepAliveSeconds * keepAliveMaxMissed` (45 s by default). `keepAliveSeconds = 0`
  disables it. sshj's default `SSH_MSG_IGNORE` heartbeat is not used because it expects no reply
  and cannot detect a dead peer.
- `SshShell.output` is a cold flow with **exactly one collector** for the shell's lifetime (a
  second collection throws `IllegalStateException`). Cancelling the collector, which usually
  interrupts a blocked read, raises only `CancellationException`; a broken connection raises
  `SshException`. `awaitExit` follows the same rules.
- `exec` caps stdout and stderr at 1 MiB each (more fails with `SshException.Protocol`, "output
  too large") and is cancellable.
- `resize` accepts 1..1000 columns and 1..500 rows (`IllegalArgumentException` otherwise).

## Other design notes

- Blocking sshj calls run on an injected `CoroutineDispatcher` (default `Dispatchers.IO`).
- On Android, `SshSecurity.install()` (called lazily by `SshjTransport`) replaces the platform's
  cut-down "BC" provider with the full BouncyCastle provider, **appended** at the end of the list
  (sshj asks for BC by name; inserting at position 1 would change every un-named JCA lookup in
  the process). On desktop the call is a no-op because sshj registers BouncyCastle itself.
- `consumer-rules.pro` keeps sshj and only the BouncyCastle provider packages
  (`jcajce.provider`, `jce.provider`, `pqc.jcajce.provider`). CI builds an R8-minified release
  APK so these rules actually run.

## Loopback preamble

When `LoopbackPreamble(port, token)` is passed, the transport opens a TCP connection to
`127.0.0.1:port`, writes the 32-byte token before anything else, and then runs the normal SSH
handshake over that socket. This is how the in-app WireGuard forwarder authenticates the client.
The constructor requires exactly 32 bytes and stores a copy; the forwarder must still reject short
reads and use a read deadline.

## Security rules

- Passwords, key material and preamble tokens never appear in exception messages or in
  `toString()` of the API types. Credential copies handed to sshj are zero-filled in `finally`.
- Text that came from the server (disconnect messages, algorithm lists) is untrusted: control and
  bidi/format characters are removed and it is capped at 200 characters before it goes into an
  exception message.
- Prefer wiping `CharArray` secrets after `connect` returns.

## Tests

`desktopTest` starts an embedded Apache MINA SSHD (test dependency only) on an OS-assigned port
(`setPort(0)`, read back after start) and covers password and public-key auth, exec (including the
output cap and cancellation), PTY shell round trip and resize validation, host-key decisions as
exception types (fingerprint and blob compared with MINA's own), a key change between two connects,
a throwing verifier, the loopback preamble, secrets in `stackTraceToString()`, connect
cancellation against a server that never speaks, output-flow cancellation, the single-collector
rule, Modern vs Legacy against a server limited to aes128-cbc + hmac-sha1 + DH group14-sha1, and
keep-alive dead-peer detection through a proxy that stops forwarding. Run with
`./gradlew :core:ssh:desktopTest`.

## Not covered yet

- Jump hosts / ProxyJump and port forwarding
- SFTP
- Keyboard-interactive and agent authentication
- `known_hosts` storage and trust-on-first-use UI (the verifier contract is ready for it)
- A re-key with a different host key is pinned in code but not exercised by a test
- Android R8 behaviour on a device (CI only builds the minified APK)
- Ed25519 / encrypted-key coverage in tests (only unencrypted RSA PKCS#8 is exercised)
