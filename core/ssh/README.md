# :core:ssh

SSH transport spike for TerminalMax. The public API (`SshTransport`, `SshSession`,
`SshShell`, ...) lives in `commonMain` and uses no JVM types. The only implementation,
`SshjTransport`, is in the `jvmCommonMain` source set shared by the Android and desktop
targets and is backed by [sshj](https://github.com/hierynomus/sshj) 0.41.2.

## Design

- Blocking sshj calls run on an injected `CoroutineDispatcher` (default `Dispatchers.IO`).
- `SshShell.output` is a cold `Flow<ByteArray>` over the channel input stream; use a single
  collector. Cancelling the collector interrupts the blocking read.
- Keep-alive is 30 s. The password array handed to sshj is a copy, so the caller keeps
  ownership of (and should wipe) its own array.
- On Android, `SshSecurity.install()` (called lazily by `SshjTransport`) replaces the
  platform's cut-down "BC" provider with the full BouncyCastle provider. On desktop the call
  is a no-op because sshj registers BouncyCastle itself.
- `consumer-rules.pro` keeps sshj and BouncyCastle for consumers that enable R8.

## Loopback preamble

When `LoopbackPreamble(port, token)` is passed, the transport opens a TCP connection to
`127.0.0.1:port`, writes the token bytes before anything else, and then runs the normal SSH
handshake over that socket. This is how the in-app WireGuard forwarder authenticates the
client. Host-key verification is independent of the socket: the `HostKeyVerifier` always
receives the real `SshTarget` host and port, never the loopback address.

## Security rules

- There is no accept-all `HostKeyVerifier` in main code. Callers must supply one.
  (Tests define their own recording verifier.)
- Passwords, private keys and preamble tokens never appear in exception messages or
  `toString()` output of the API types.
- Prefer wiping `CharArray` secrets after `connect` returns.

## Tests

`desktopTest` starts an embedded Apache MINA SSHD (test dependency only) on 127.0.0.1 and
covers password auth, public-key auth (RSA, PKCS#8 PEM), exec, a PTY shell round trip with
resize, host-key rejection, the loopback preamble (right and wrong token) and a wrong
password. Run with `./gradlew :core:ssh:desktopTest`.

## Not covered yet

- Jump hosts / ProxyJump and port forwarding
- SFTP
- Keyboard-interactive and agent authentication
- Legacy algorithm toggles (for example RouterOS 6 era ciphers, KEX and host keys)
- `known_hosts` storage and trust-on-first-use UI
- Android R8 verification on a device (the keep rules are untested)
- Ed25519 / encrypted-key coverage in tests (only unencrypted RSA PKCS#8 is exercised)
