// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import kotlinx.coroutines.flow.Flow

/** Where to connect. [host]/[port] are also the identity used for host-key verification. */
data class SshTarget(
    val host: String,
    val port: Int = 22,
    val username: String,
)

/** Credentials. Both variants redact their secrets in [toString]. */
sealed interface SshAuth {
    class Password(val password: CharArray) : SshAuth {
        override fun toString(): String = "SshAuth.Password(***)"
    }

    /** [pem] is the full text of an OpenSSH or PEM (PKCS#8) private key. */
    class PrivateKey(val pem: String, val passphrase: CharArray? = null) : SshAuth {
        override fun toString(): String = "SshAuth.PrivateKey(***)"
    }
}

/** Outcome of looking a presented host key up in the caller's trust store. */
enum class HostKeyDecision {
    /** The key is stored for this host and matches. */
    Trusted,

    /** Nothing is stored for this host (or for this key type): ask the user, then reconnect. */
    Unknown,

    /** A different key is stored for this host: possible man-in-the-middle. */
    Mismatch,
}

/**
 * Looks a server host key up in the caller's trust store. There is deliberately no accept-all
 * implementation in main code.
 *
 * This is a **pure lookup**: it runs on an SSH reader thread in the middle of key exchange, so
 * it must be fast, must not block and must not prompt. To support trust-on-first-use, return
 * [HostKeyDecision.Unknown]; [SshTransport.connect] then fails with
 * [SshException.HostKeyUnknown], the UI asks the user, stores the key and connects again.
 *
 * The transport pins the accepted key blob for the life of the connection: a later key exchange
 * (re-key) must present the identical key, otherwise the connection fails with
 * [SshException.HostKeyChanged] without consulting the verifier again.
 *
 * An exception thrown from [check] or [knownKeyTypes] fails the connect with
 * [SshException.Protocol] whose cause is that exception.
 */
fun interface HostKeyVerifier {
    /**
     * @param host the real target host (never the loopback forwarder address).
     * @param port the real target port.
     * @param keyType SSH key type name, for example `ssh-ed25519` or `ssh-rsa`.
     * @param fingerprintSha256 OpenSSH style, "SHA256:" followed by unpadded base64.
     * @param key SSH wire-format public key blob (as in an authorized_keys base64 field).
     */
    fun check(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): HostKeyDecision

    /**
     * Key types (for example `ssh-ed25519`) already stored for [host]:[port], most preferred
     * first. The transport asks the server for these types first so that a known host does not
     * look unknown just because the server offers another key type first.
     */
    fun knownKeyTypes(host: String, port: Int): List<String> = emptyList()
}

data class PtyRequest(
    val term: String = "xterm-256color",
    val cols: Int = 80,
    val rows: Int = 24,
) {
    init {
        require(cols in MIN_COLS..MAX_COLS) { "cols must be in $MIN_COLS..$MAX_COLS" }
        require(rows in MIN_ROWS..MAX_ROWS) { "rows must be in $MIN_ROWS..$MAX_ROWS" }
    }
}

internal const val MIN_COLS = 1
internal const val MAX_COLS = 1000
internal const val MIN_ROWS = 1
internal const val MAX_ROWS = 500

/**
 * An interactive remote shell.
 *
 * [output] supports exactly one collector for the lifetime of the shell; a second collection
 * (even after the first one was cancelled) fails with [IllegalStateException].
 */
interface SshShell {
    /**
     * Remote output (stdout and, with a PTY, stderr). Completes when the remote side closes.
     * Cancelling the collector is not an error: only [kotlinx.coroutines.CancellationException]
     * is raised. A broken connection surfaces as [SshException].
     */
    val output: Flow<ByteArray>

    suspend fun write(bytes: ByteArray)

    /** @throws IllegalArgumentException if [cols] is not in 1..1000 or [rows] is not in 1..500. */
    suspend fun resize(cols: Int, rows: Int)

    /** Suspends until the shell ends; returns the exit status, or null if none was reported. */
    suspend fun awaitExit(): Int?

    fun close()
}

/** Output of [SshSession.exec]. stdout and stderr are each capped at 1 MiB. */
class ExecResult(
    val exitCode: Int?,
    val stdout: ByteArray,
    val stderr: ByteArray,
) {
    override fun toString(): String =
        "ExecResult(exitCode=$exitCode, stdout=${stdout.size}B, stderr=${stderr.size}B)"
}

/** What the client and server agreed on during (the latest) key exchange. */
data class NegotiatedAlgorithms(
    val kex: String,
    /** Host-key signature algorithm, for example `ssh-ed25519` or `rsa-sha2-512`. */
    val hostKey: String,
    val cipherC2s: String,
    val cipherS2c: String,
    val macC2s: String,
    val macS2c: String,
)

interface SshSession {
    /** Algorithms of the latest key exchange. */
    val negotiated: NegotiatedAlgorithms

    /**
     * True when anything outside the [AlgorithmProfile.Modern] lists was negotiated (only
     * possible with [AlgorithmProfile.Legacy]). Show a warning badge for these sessions. MACs
     * are not considered when an AEAD cipher (chacha20-poly1305, AES-GCM) was negotiated.
     */
    val usesLegacyCrypto: Boolean

    suspend fun openShell(pty: PtyRequest = PtyRequest()): SshShell

    /**
     * Runs [command] and collects its output. Stdout and stderr are each limited to 1 MiB; more
     * fails with [SshException.Protocol]. Cancellable: cancelling closes the command's channel.
     */
    suspend fun exec(command: String): ExecResult

    fun close()
}

/**
 * When present, the transport connects to 127.0.0.1:[port] and writes [token] before the SSH
 * protocol starts. This authenticates the client to the in-app WireGuard forwarder. Host-key
 * verification still uses the real target host and port.
 *
 * The token must be exactly [TOKEN_SIZE] bytes; it is copied, so the caller may wipe its array.
 */
class LoopbackPreamble(val port: Int, token: ByteArray) {
    private val stored: ByteArray

    init {
        require(port in 1..65535) { "port must be in 1..65535" }
        require(token.size == TOKEN_SIZE) { "token must be $TOKEN_SIZE bytes" }
        stored = token.copyOf()
    }

    /** A fresh copy of the token on every call; callers should wipe it after use. */
    val token: ByteArray get() = stored.copyOf()

    override fun toString(): String = "LoopbackPreamble(port=$port, token=***)"

    companion object {
        const val TOKEN_SIZE = 32
    }
}

/**
 * Which algorithm lists the client offers. There is **no automatic fallback** from [Modern] to
 * [Legacy]: a network attacker can force a failed handshake with a TCP reset, so falling back
 * would turn into a downgrade. [Legacy] must be a per-host choice made by the user.
 */
enum class AlgorithmProfile {
    /**
     * Key exchange: curve25519, ECDH, DH group exchange SHA-256 and DH groups 14-18 with SHA-2.
     * Ciphers: ChaCha20-Poly1305, AES-GCM, AES-CTR. MACs: HMAC-SHA-2 (encrypt-then-MAC first).
     * Host keys: Ed25519, ECDSA, RSA with SHA-2.
     */
    Modern,

    /**
     * [Modern] plus, appended after it so that they only win when the server offers nothing
     * better: DH group14-sha1, group-exchange-sha1 and group1-sha1; AES-CBC and 3DES-CBC;
     * HMAC-SHA1; `ssh-rsa` (SHA-1) and `ssh-dss` host keys. Never RC4, MD5 or `none`.
     */
    Legacy,
}

/**
 * @property connectTimeoutMillis TCP connect timeout, and the time sshj waits for each protocol
 *   step (key exchange, each authentication method, opening a channel).
 * @property keepAliveSeconds interval of `keepalive@openssh.com` requests; 0 disables keep-alive.
 * @property keepAliveMaxMissed the connection is declared dead after this many unanswered
 *   keep-alives, so dead-peer detection takes roughly keepAliveSeconds * keepAliveMaxMissed.
 */
data class SshConnectOptions(
    val connectTimeoutMillis: Int = 15_000,
    val keepAliveSeconds: Int = 15,
    val keepAliveMaxMissed: Int = 3,
    val algorithms: AlgorithmProfile = AlgorithmProfile.Modern,
) {
    init {
        require(connectTimeoutMillis > 0) { "connectTimeoutMillis must be positive" }
        require(keepAliveSeconds >= 0) { "keepAliveSeconds must not be negative" }
        require(keepAliveMaxMissed >= 1) { "keepAliveMaxMissed must be at least 1" }
    }
}

interface SshTransport {
    /**
     * Connects and authenticates. Cancellable: cancelling closes the socket and any half-open
     * connection, so `withTimeout(...) { connect(...) }` is a real overall deadline.
     *
     * @throws SshException on failure. Cancellation is reported as
     *   [kotlinx.coroutines.CancellationException], never as an [SshException].
     */
    suspend fun connect(
        target: SshTarget,
        auth: SshAuth,
        hostKeyVerifier: HostKeyVerifier,
        via: LoopbackPreamble? = null,
        options: SshConnectOptions = SshConnectOptions(),
    ): SshSession
}

/**
 * Failure of an SSH operation. Messages never contain passwords, key material or tokens, and
 * text that came from the server is sanitised (control characters removed, length capped).
 */
sealed class SshException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** The server presented a key that the [HostKeyVerifier] does not know. Prompt, then reconnect. */
    class HostKeyUnknown(
        val host: String,
        val port: Int,
        val keyType: String,
        val fingerprintSha256: String,
        val key: ByteArray,
        cause: Throwable? = null,
    ) : SshException("Host key of $host:$port is not known ($keyType $fingerprintSha256)", cause)

    /** The server presented a key that differs from the one on record (or changed it during a re-key). */
    class HostKeyChanged(
        val host: String,
        val port: Int,
        val keyType: String,
        val fingerprintSha256: String,
        val key: ByteArray,
        cause: Throwable? = null,
    ) : SshException("Host key of $host:$port has changed ($keyType $fingerprintSha256)", cause)

    /** Wrong password or key, key could not be decrypted, or no acceptable authentication method. */
    class AuthFailed(message: String, cause: Throwable? = null) : SshException(message, cause)

    /** Connect, handshake, keep-alive or another protocol step timed out. */
    class Timeout(message: String, cause: Throwable? = null) : SshException(message, cause)

    /** The target (or the loopback forwarder) could not be reached. */
    class Unreachable(message: String, cause: Throwable? = null) : SshException(message, cause)

    /** Any other failure: protocol errors, no common algorithms, broken connection, oversized output. */
    class Protocol(message: String, cause: Throwable? = null) : SshException(message, cause)
}
