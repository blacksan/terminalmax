// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.net.SocketFactory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.connection.channel.direct.PTYMode
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.password.PasswordUtils

/** [SshTransport] backed by sshj. All blocking calls run on [dispatcher]. */
class SshjTransport(
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : SshTransport {

    override suspend fun connect(
        target: SshTarget,
        auth: SshAuth,
        hostKeyVerifier: HostKeyVerifier,
        via: LoopbackPreamble?,
        connectTimeoutMillis: Int,
    ): SshSession = withContext(dispatcher) {
        installSecurityProvider()
        val client = SSHClient()
        val adapter = HostKeyAdapter(target, hostKeyVerifier)
        try {
            client.setConnectTimeout(connectTimeoutMillis)
            // Read timeout only while connecting/authenticating; reset below.
            client.setTimeout(connectTimeoutMillis)
            client.setSocketFactory(PreambleSocketFactory(via, connectTimeoutMillis))
            client.addHostKeyVerifier(adapter)
            // connect(host, port) with a socket factory that returns an already connected
            // socket (via) skips sshj's own connect; the name is only used for logging here.
            client.connect(target.host, target.port)
            authenticate(client, target, auth)
            client.setTimeout(0)
            client.connection.keepAlive.setKeepAliveInterval(KEEP_ALIVE_SECONDS)
            SshjSession(client, dispatcher)
        } catch (t: Throwable) {
            runCatching { client.close() }
            throw toSshException(t, adapter, auth)
        }
    }

    private fun authenticate(client: SSHClient, target: SshTarget, auth: SshAuth) {
        when (auth) {
            // sshj blanks the array it is given, so hand it a copy and keep the caller's intact.
            is SshAuth.Password -> client.authPassword(target.username, auth.password.copyOf())
            is SshAuth.PrivateKey -> {
                val finder = auth.passphrase?.let { PasswordUtils.createOneOff(it.copyOf()) }
                val provider: KeyProvider = client.loadKeys(auth.pem, null, finder)
                client.authPublickey(target.username, provider)
            }
        }
    }

    private fun toSshException(t: Throwable, adapter: HostKeyAdapter, auth: SshAuth): SshException {
        if (t is SshException) return t
        if (adapter.rejected) {
            return SshException("Host key was rejected by the verifier", t)
        }
        val reason = redact(t.message.orEmpty(), auth)
        return SshException("SSH connection failed (${t.javaClass.simpleName}): $reason", t)
    }

    private fun redact(text: String, auth: SshAuth): String {
        var out = text
        if (auth is SshAuth.Password && auth.password.isNotEmpty()) {
            out = out.replace(String(auth.password), "***")
        }
        if (auth is SshAuth.PrivateKey && auth.pem.isNotEmpty()) {
            out = out.replace(auth.pem, "***")
        }
        return out
    }

    /**
     * Adapts our verifier to sshj. sshj's own hostname/port arguments are ignored on purpose:
     * with a loopback preamble sshj's remote port would be the forwarder's port, so the real
     * target identity is always taken from [target].
     */
    private class HostKeyAdapter(
        private val target: SshTarget,
        private val verifier: HostKeyVerifier,
    ) : net.schmizz.sshj.transport.verification.HostKeyVerifier {
        @Volatile
        var rejected = false
            private set

        override fun verify(hostname: String?, port: Int, key: PublicKey): Boolean {
            val accepted = try {
                val blob = Buffer.PlainBuffer().putPublicKey(key).compactData
                val digest = MessageDigest.getInstance("SHA-256").digest(blob)
                val fingerprint = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest)
                verifier.verify(target.host, target.port, KeyType.fromKey(key).toString(), fingerprint, blob)
            } catch (e: Exception) {
                false
            }
            if (!accepted) rejected = true
            return accepted
        }

        override fun findExistingAlgorithms(hostname: String?, port: Int): List<String> = emptyList()
    }

    /** Hands sshj an already connected socket (preamble written) when [via] is set. */
    private class PreambleSocketFactory(
        private val via: LoopbackPreamble?,
        private val timeoutMillis: Int,
    ) : SocketFactory() {
        override fun createSocket(): Socket {
            val preamble = via ?: return Socket()
            val socket = Socket()
            try {
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(InetAddress.getByAddress(LOOPBACK), preamble.port), timeoutMillis)
                socket.getOutputStream().apply {
                    write(preamble.token)
                    flush()
                }
                return socket
            } catch (e: IOException) {
                runCatching { socket.close() }
                // Do not expose the token; the cause is an I/O error without it.
                throw IOException("Could not reach the loopback forwarder", e)
            }
        }

        override fun createSocket(host: String?, port: Int): Socket = unsupported()
        override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket = unsupported()
        override fun createSocket(host: InetAddress?, port: Int): Socket = unsupported()
        override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
            unsupported()

        private fun unsupported(): Nothing = throw UnsupportedOperationException("Use createSocket()")
    }

    private companion object {
        const val KEEP_ALIVE_SECONDS = 30
        val LOOPBACK = byteArrayOf(127, 0, 0, 1)
    }
}

private class SshjSession(
    private val client: SSHClient,
    private val dispatcher: CoroutineDispatcher,
) : SshSession {

    override suspend fun openShell(pty: PtyRequest): SshShell = withContext(dispatcher) {
        try {
            val session = client.startSession()
            try {
                session.allocatePTY(pty.term, pty.cols, pty.rows, 0, 0, emptyMap<PTYMode, Int>())
                SshjShell(session, session.startShell(), dispatcher)
            } catch (t: Throwable) {
                runCatching { session.close() }
                throw t
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            throw SshException("Could not open shell (${t.javaClass.simpleName})", t)
        }
    }

    override suspend fun exec(command: String): ExecResult = withContext(dispatcher) {
        try {
            val session = client.startSession()
            try {
                val cmd = session.exec(command)
                coroutineScope {
                    val err = async { cmd.errorStream.readBytes() }
                    val out = cmd.inputStream.readBytes()
                    val errBytes = err.await()
                    runCatching { cmd.join(EXIT_WAIT_SECONDS, TimeUnit.SECONDS) }
                    ExecResult(cmd.exitStatus, out, errBytes)
                }
            } finally {
                runCatching { session.close() }
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            throw SshException("Command failed (${t.javaClass.simpleName})", t)
        }
    }

    override fun close() {
        runCatching { client.close() }
    }

    private companion object {
        const val EXIT_WAIT_SECONDS = 5L
    }
}

private class SshjShell(
    private val session: Session,
    private val shell: Session.Shell,
    private val dispatcher: CoroutineDispatcher,
) : SshShell {
    private val writeLock = Mutex()

    /** Cold flow; each collection reads from the same channel stream, so use one collector. */
    override val output: Flow<ByteArray> = flow {
        val input = shell.inputStream
        val buffer = ByteArray(BUFFER_SIZE)
        while (true) {
            val n = runInterruptible(dispatcher) { input.read(buffer) }
            if (n < 0) break
            if (n > 0) emit(buffer.copyOf(n))
        }
    }

    override suspend fun write(bytes: ByteArray) {
        writeLock.withLock {
            withContext(dispatcher) {
                try {
                    val out = shell.outputStream
                    out.write(bytes)
                    out.flush()
                } catch (e: IOException) {
                    throw SshException("Write to shell failed", e)
                }
            }
        }
    }

    override suspend fun resize(cols: Int, rows: Int) {
        withContext(dispatcher) {
            try {
                shell.changeWindowDimensions(cols, rows, 0, 0)
            } catch (e: IOException) {
                throw SshException("Window resize failed", e)
            }
        }
    }

    override suspend fun awaitExit(): Int? = runInterruptible(dispatcher) {
        shell.join()
        (shell as? Session.Command)?.exitStatus
    }

    override fun close() {
        runCatching { shell.close() }
        runCatching { session.close() }
    }

    private companion object {
        const val BUFFER_SIZE = 8192
    }
}
