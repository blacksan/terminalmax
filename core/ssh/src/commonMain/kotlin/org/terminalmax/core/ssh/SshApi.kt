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

/**
 * Decides whether a server host key is trusted. There is deliberately no accept-all
 * implementation in main code: callers must supply their own (for example a known_hosts
 * store or a trust-on-first-use prompt).
 *
 * @param fingerprintSha256 OpenSSH style, "SHA256:" followed by unpadded base64.
 * @param key SSH wire-format public key blob (as in an authorized_keys base64 field).
 */
fun interface HostKeyVerifier {
    fun verify(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): Boolean
}

data class PtyRequest(
    val term: String = "xterm-256color",
    val cols: Int = 80,
    val rows: Int = 24,
)

/** An interactive remote shell. [output] must be collected by a single collector. */
interface SshShell {
    /** Remote output (stdout and, with a PTY, stderr). Completes when the remote side closes. */
    val output: Flow<ByteArray>

    suspend fun write(bytes: ByteArray)

    suspend fun resize(cols: Int, rows: Int)

    /** Suspends until the shell ends; returns the exit status, or null if none was reported. */
    suspend fun awaitExit(): Int?

    fun close()
}

class ExecResult(
    val exitCode: Int?,
    val stdout: ByteArray,
    val stderr: ByteArray,
) {
    override fun toString(): String =
        "ExecResult(exitCode=$exitCode, stdout=${stdout.size}B, stderr=${stderr.size}B)"
}

interface SshSession {
    suspend fun openShell(pty: PtyRequest = PtyRequest()): SshShell

    suspend fun exec(command: String): ExecResult

    fun close()
}

/**
 * When present, the transport connects to 127.0.0.1:[port] and writes [token] before the SSH
 * protocol starts. This authenticates the client to the in-app WireGuard forwarder. Host-key
 * verification still uses the real target host and port.
 */
class LoopbackPreamble(val port: Int, val token: ByteArray) {
    override fun toString(): String = "LoopbackPreamble(port=$port, token=***)"
}

interface SshTransport {
    suspend fun connect(
        target: SshTarget,
        auth: SshAuth,
        hostKeyVerifier: HostKeyVerifier,
        via: LoopbackPreamble? = null,
        connectTimeoutMillis: Int = 15000,
    ): SshSession
}

/** Failure of an SSH operation. Messages never contain passwords, key material or tokens. */
class SshException(message: String, cause: Throwable? = null) : Exception(message, cause)
