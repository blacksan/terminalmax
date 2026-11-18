// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NoRouteToHostException
import java.net.PortUnreachableException
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.MessageDigest
import java.security.PublicKey
import java.util.Base64
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.SocketFactory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.asExecutor
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.resumeWithException
import net.schmizz.keepalive.KeepAliveRunner
import net.schmizz.sshj.SSHClient
import net.schmizz.sshj.common.Buffer
import net.schmizz.sshj.common.KeyType
import net.schmizz.sshj.connection.channel.direct.PTYMode
import net.schmizz.sshj.connection.channel.direct.Session
import net.schmizz.sshj.connection.channel.direct.SessionChannel
import net.schmizz.sshj.transport.verification.AlgorithmsVerifier
import net.schmizz.sshj.userauth.UserAuthException
import net.schmizz.sshj.userauth.keyprovider.KeyProvider
import net.schmizz.sshj.userauth.password.PasswordUtils
import net.schmizz.sshj.transport.NegotiatedAlgorithms as SshjNegotiatedAlgorithms

/** [SshTransport] backed by sshj. All blocking calls run on [dispatcher]. */
class SshjTransport(
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
) : SshTransport {

    override suspend fun connect(
        target: SshTarget,
        auth: SshAuth,
        hostKeyVerifier: HostKeyVerifier,
        via: LoopbackPreamble?,
        options: SshConnectOptions,
    ): SshSession {
        // The first call builds the (self-testing) sshj configs; keep that off the caller's thread.
        val config = try {
            withContext(dispatcher) {
                installSecurityProvider()
                SshjConfigs.forProfile(options.algorithms)
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            throw SshException.Protocol("SSH crypto setup failed (${e.javaClass.simpleName})", e)
        }

        val client = SSHClient(config)
        val adapter = HostKeyAdapter(target, hostKeyVerifier)
        val algorithms = AlgorithmTracker()
        val sockets = PreambleSocketFactory(via, options.connectTimeoutMillis)

        return suspendCancellableCoroutine<SshSession> { cont ->
            // Closing the socket (which the factory may still be opening) unblocks every blocking
            // sshj call below, so cancelling really stops the handshake. The socket goes first so that
            // sshj's own disconnect (which tries to write) fails fast instead of waiting on a dead peer.
            cont.invokeOnCancellation {
                sockets.abort()
                quietly { client.close() }
            }
            dispatcher.asExecutor().execute {
                try {
                    client.setConnectTimeout(options.connectTimeoutMillis)
                    // Socket read timeout; only bounds the identification-string read, sshj's reader
                    // thread ignores SocketTimeoutException afterwards.
                    client.setTimeout(options.connectTimeoutMillis)
                    // How long sshj waits for key exchange, each auth method and channel requests.
                    client.transport.setTimeoutMs(options.connectTimeoutMillis)
                    client.setSocketFactory(sockets)
                    client.addHostKeyVerifier(adapter)
                    client.transport.addAlgorithmsVerifier(algorithms)

                    // The keep-alive thread starts during connect() and only if the interval is
                    // already > 0, so this must be configured before connecting.
                    val keepAlive = client.connection.keepAlive
                    keepAlive.setKeepAliveInterval(options.keepAliveSeconds)
                    (keepAlive as? KeepAliveRunner)?.setMaxAliveCount(options.keepAliveMaxMissed)

                    // With a preamble the factory returns an already connected socket, so sshj does
                    // not resolve the host name itself; the name is only used for logging.
                    client.connect(target.host, target.port)
                    authenticate(client, target, auth)
                    if (algorithms.current == null) {
                        throw SshException.Protocol("Key exchange did not report the negotiated algorithms")
                    }
                    val session = SshjSession(client, dispatcher, algorithms) { adapter.failure }
                    // If the coroutine was cancelled meanwhile, the session is closed here.
                    cont.resume(session) { _, value, _ -> value.close() }
                } catch (e: Exception) {
                    quietly { client.close() }
                    cont.resumeWithException(mapConnectFailure(e, adapter))
                } catch (e: Error) {
                    // Do not wrap Errors as SshException, but do not leave the caller hanging either.
                    quietly { client.close() }
                    cont.resumeWithException(e)
                }
            }
        }
    }

    private fun authenticate(client: SSHClient, target: SshTarget, auth: SshAuth) {
        when (auth) {
            is SshAuth.Password -> {
                // sshj blanks the array it is given, so hand it a copy, and wipe that copy
                // ourselves in case sshj never asked for it.
                val copy = auth.password.copyOf()
                try {
                    client.authPassword(target.username, copy)
                } finally {
                    copy.fill('\u0000')
                }
            }
            is SshAuth.PrivateKey -> {
                val passphrase = auth.passphrase?.copyOf()
                try {
                    val finder = passphrase?.let { PasswordUtils.createOneOff(it) }
                    val provider: KeyProvider = try {
                        client.loadKeys(auth.pem, null, finder)
                    } catch (e: Exception) {
                        throw SshException.AuthFailed("Could not load the private key (wrong passphrase or unsupported format)", e)
                    }
                    client.authPublickey(target.username, provider)
                } finally {
                    passphrase?.fill('\u0000')
                }
            }
        }
    }

    private fun mapConnectFailure(e: Exception, adapter: HostKeyAdapter): SshException {
        // A host-key problem found by the adapter is the real reason, whatever sshj then threw.
        adapter.failure?.let { return it }
        if (e is SshException) return e
        return classifyFailure("SSH connection failed", e)
    }

    /**
     * Adapts our verifier to sshj. sshj's own hostname/port arguments are ignored on purpose:
     * with a loopback preamble sshj's remote port would be the forwarder's port, so the real
     * target identity is always taken from [target].
     *
     * The first accepted key blob is pinned: later key exchanges must present the same key.
     */
    private class HostKeyAdapter(
        private val target: SshTarget,
        private val verifier: HostKeyVerifier,
    ) : net.schmizz.sshj.transport.verification.HostKeyVerifier {

        /** Why the host key was refused; null while nothing went wrong. Only the first failure is kept. */
        @Volatile
        var failure: SshException? = null
            private set

        private var pinned: ByteArray? = null // guarded by this

        @Synchronized
        override fun verify(hostname: String?, port: Int, key: PublicKey): Boolean {
            if (failure != null) return false
            try {
                val blob = Buffer.PlainBuffer().putPublicKey(key).compactData
                val keyType = KeyType.fromKey(key).toString()
                val digest = MessageDigest.getInstance("SHA-256").digest(blob)
                val fingerprint = "SHA256:" + Base64.getEncoder().withoutPadding().encodeToString(digest)

                val pin = pinned
                if (pin != null) {
                    if (MessageDigest.isEqual(pin, blob)) return true
                    fail(SshException.HostKeyChanged(target.host, target.port, keyType, fingerprint, blob.copyOf()))
                    return false
                }
                when (verifier.check(target.host, target.port, keyType, fingerprint, blob.copyOf())) {
                    HostKeyDecision.Trusted -> {
                        pinned = blob.copyOf()
                        return true
                    }
                    HostKeyDecision.Unknown ->
                        fail(SshException.HostKeyUnknown(target.host, target.port, keyType, fingerprint, blob.copyOf()))
                    HostKeyDecision.Mismatch ->
                        fail(SshException.HostKeyChanged(target.host, target.port, keyType, fingerprint, blob.copyOf()))
                }
                return false
            } catch (e: Exception) {
                fail(SshException.Protocol("Host key verifier failed (${e.javaClass.simpleName})", e))
                return false
            }
        }

        override fun findExistingAlgorithms(hostname: String?, port: Int): List<String> =
            try {
                verifier.knownKeyTypes(target.host, target.port)
            } catch (e: Exception) {
                fail(SshException.Protocol("Host key verifier failed (${e.javaClass.simpleName})", e))
                emptyList()
            }

        @Synchronized
        private fun fail(e: SshException) {
            if (failure == null) failure = e
        }
    }

    /**
     * Hands sshj an already connected socket (preamble written) when a preamble is set. Remembers
     * the socket it created so that [abort] can close it even before sshj has stored it.
     */
    private class PreambleSocketFactory(
        private val via: LoopbackPreamble?,
        private val timeoutMillis: Int,
    ) : SocketFactory() {
        @Volatile
        private var aborted = false

        @Volatile
        private var current: Socket? = null

        fun abort() {
            aborted = true
            quietly { current?.close() }
        }

        override fun createSocket(): Socket {
            val socket = Socket()
            current = socket
            if (aborted) {
                quietly { socket.close() }
                throw IOException("Connection attempt was cancelled")
            }
            val preamble = via ?: return socket
            try {
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(InetAddress.getByAddress(LOOPBACK), preamble.port), timeoutMillis)
                val token = preamble.token
                try {
                    socket.getOutputStream().apply {
                        write(token)
                        flush()
                    }
                } finally {
                    token.fill(0)
                }
                return socket
            } catch (e: IOException) {
                quietly { socket.close() }
                // Do not expose the token; the cause is an I/O error without it.
                throw ForwarderUnreachableException(e)
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
        val LOOPBACK = byteArrayOf(127, 0, 0, 1)
    }
}

/** Records the algorithms of every key exchange; never vetoes one (the configs already restrict them). */
private class AlgorithmTracker : AlgorithmsVerifier {
    @Volatile
    var current: NegotiatedAlgorithms? = null
        private set

    override fun verify(algorithms: SshjNegotiatedAlgorithms): Boolean {
        current = NegotiatedAlgorithms(
            kex = algorithms.getKeyExchangeAlgorithm(),
            hostKey = algorithms.getSignatureAlgorithm(),
            cipherC2s = algorithms.getClient2ServerCipherAlgorithm(),
            cipherS2c = algorithms.getServer2ClientCipherAlgorithm(),
            macC2s = algorithms.getClient2ServerMACAlgorithm(),
            macS2c = algorithms.getServer2ClientMACAlgorithm(),
        )
        return true
    }
}

private class ForwarderUnreachableException(cause: Throwable) :
    IOException("Could not reach the loopback forwarder", cause)

private class SshjSession(
    private val client: SSHClient,
    private val dispatcher: CoroutineDispatcher,
    private val algorithms: AlgorithmTracker,
    private val hostKeyFailure: () -> SshException?,
) : SshSession {

    override val negotiated: NegotiatedAlgorithms
        get() = checkNotNull(algorithms.current) { "No key exchange completed" }

    override val usesLegacyCrypto: Boolean
        get() = SshAlgorithms.isLegacy(negotiated)

    override suspend fun openShell(pty: PtyRequest): SshShell {
        val session = blocking("Could not open shell") { client.startSession() }
        try {
            val shell = blocking("Could not open shell") {
                session.allocatePTY(pty.term, pty.cols, pty.rows, 0, 0, emptyMap<PTYMode, Int>())
                session.startShell()
            }
            return SshjShell(session, shell, dispatcher, hostKeyFailure)
        } catch (e: Exception) {
            closeInBackground(dispatcher, session)
            throw e
        }
    }

    override suspend fun exec(command: String): ExecResult {
        val session = blocking("Could not open session") { client.startSession() }
        try {
            val cmd = blocking("Could not start command") { session.exec(command) }
            return coroutineScope {
                val err = async { blocking("Reading command output failed") { cmd.errorStream.readCapped("stderr") } }
                val out = blocking("Reading command output failed") { cmd.inputStream.readCapped("stdout") }
                val errBytes = err.await()
                try {
                    blocking("Waiting for command exit failed") { cmd.join(EXIT_WAIT_SECONDS, TimeUnit.SECONDS) }
                } catch (_: SshException) {
                    // The exit status is best effort; output has been read completely.
                }
                ExecResult(cmd.exitStatus, out, errBytes)
            }
        } finally {
            closeInBackground(dispatcher, session)
        }
    }

    override fun close() {
        quietly { client.close() }
    }

    private suspend fun <T> blocking(what: String, block: () -> T): T =
        sshBlocking(dispatcher, what, hostKeyFailure, block)

    private fun InputStream.readCapped(stream: String): ByteArray {
        val sink = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val n = read(buffer)
            if (n < 0) break
            if (sink.size() + n > MAX_EXEC_OUTPUT_BYTES) {
                throw SshException.Protocol("Command output too large: $stream exceeds $MAX_EXEC_OUTPUT_BYTES bytes")
            }
            sink.write(buffer, 0, n)
        }
        return sink.toByteArray()
    }

    private companion object {
        const val EXIT_WAIT_SECONDS = 5L
        const val MAX_EXEC_OUTPUT_BYTES = 1024 * 1024
    }
}

private class SshjShell(
    private val session: Session,
    private val shell: Session.Shell,
    private val dispatcher: CoroutineDispatcher,
    private val hostKeyFailure: () -> SshException?,
) : SshShell {
    private val writeLock = Mutex()
    private val collected = AtomicBoolean(false)

    /** Cold flow over the channel stream; supports exactly one collector. */
    override val output: Flow<ByteArray> = flow {
        check(collected.compareAndSet(false, true)) { "SshShell.output supports exactly one collector" }
        val input = shell.inputStream
        val buffer = ByteArray(BUFFER_SIZE)
        while (true) {
            // Cancellation while blocked in read() surfaces as InterruptedIOException; sshBlocking
            // turns that into a CancellationException instead of an IOException.
            val n = sshBlocking(dispatcher, "Shell stream failed", hostKeyFailure) { input.read(buffer) }
            if (n < 0) break
            if (n > 0) emit(buffer.copyOf(n))
        }
    }

    override suspend fun write(bytes: ByteArray) {
        writeLock.withLock {
            sshBlocking(dispatcher, "Write to shell failed", hostKeyFailure) {
                val out = shell.outputStream
                out.write(bytes)
                out.flush()
            }
        }
    }

    override suspend fun resize(cols: Int, rows: Int) {
        require(cols in MIN_COLS..MAX_COLS) { "cols must be in $MIN_COLS..$MAX_COLS" }
        require(rows in MIN_ROWS..MAX_ROWS) { "rows must be in $MIN_ROWS..$MAX_ROWS" }
        sshBlocking(dispatcher, "Window resize failed", hostKeyFailure) {
            shell.changeWindowDimensions(cols, rows, 0, 0)
        }
    }

    override suspend fun awaitExit(): Int? =
        sshBlocking(dispatcher, "Waiting for shell exit failed", hostKeyFailure) {
            shell.join()
            (shell as? SessionChannel)?.exitStatus
        }

    override fun close() {
        quietly { shell.close() }
        quietly { session.close() }
    }

    private companion object {
        const val BUFFER_SIZE = 8192
    }
}

/**
 * Runs blocking sshj code on [dispatcher] so that cancelling the coroutine interrupts it.
 *
 * - sshj reports an interrupt as an [IOException] (`InterruptedIOException`, or a
 *   `ConnectionException` caused by an `InterruptedException`), which `runInterruptible` does
 *   not recognise. Such interrupts are re-thrown as [InterruptedException] so that they become a
 *   [CancellationException] instead of an uncaught crash.
 * - Any other failure while the coroutine is being cancelled is dropped in favour of the
 *   cancellation ([ensureActive]); otherwise it is mapped to an [SshException].
 */
private suspend fun <T> sshBlocking(
    dispatcher: CoroutineDispatcher,
    what: String,
    hostKeyFailure: () -> SshException?,
    block: () -> T,
): T {
    try {
        return runInterruptible(dispatcher) {
            try {
                block()
            } catch (e: IOException) {
                if (hasInterruptCause(e)) throw InterruptedException("Interrupted").also { it.initCause(e) }
                throw e
            }
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: SshException) {
        throw e
    } catch (e: Exception) {
        currentCoroutineContext().ensureActive()
        throw hostKeyFailure() ?: classifyFailure(what, e)
    }
}

/** Closes [closeable] without making the caller wait for the remote side (close can block for a timeout). */
private fun closeInBackground(dispatcher: CoroutineDispatcher, closeable: Closeable) {
    try {
        dispatcher.asExecutor().execute { quietly { closeable.close() } }
    } catch (_: RejectedExecutionException) {
        quietly { closeable.close() }
    }
}

private inline fun quietly(block: () -> Unit) {
    try {
        block()
    } catch (_: Exception) {
        // best effort
    }
}

private fun causeChain(t: Throwable): List<Throwable> {
    val chain = ArrayList<Throwable>()
    var current: Throwable? = t
    while (current != null) {
        val c = current
        if (chain.size >= MAX_CAUSE_DEPTH || chain.any { it === c }) break
        chain.add(c)
        current = c.cause
    }
    return chain
}

private fun hasInterruptCause(t: Throwable): Boolean =
    causeChain(t).any { it is InterruptedException || it is InterruptedIOException }

/** Maps a low-level failure to the public [SshException] hierarchy. */
private fun classifyFailure(what: String, t: Throwable): SshException {
    val chain = causeChain(t)
    return when {
        chain.any { it is UserAuthException } -> SshException.AuthFailed("Authentication failed", t)
        chain.any { it is SocketTimeoutException || it is TimeoutException || it.message.orEmpty().contains("keep-alive response") } ->
            SshException.Timeout("$what: timed out", t)
        chain.any {
            it is ForwarderUnreachableException || it is ConnectException || it is UnknownHostException ||
                it is NoRouteToHostException || it is PortUnreachableException
        } -> SshException.Unreachable("$what: target unreachable", t)
        chain.any { it.message.orEmpty().startsWith("Unable to reach a settlement") } ->
            SshException.Protocol(
                "$what: no common algorithms with the server " +
                    "(an older device may need the Legacy algorithm profile)",
                t,
            )
        else -> {
            val remote = sanitizeRemoteText(t.message)
            SshException.Protocol(
                if (remote.isEmpty()) "$what (${t.javaClass.simpleName})" else "$what (${t.javaClass.simpleName}): $remote",
                t,
            )
        }
    }
}

/**
 * Text that may come from the remote side (disconnect messages, banners, algorithm lists) is
 * attacker-controlled: drop control, format (bidi override, zero width) and line/paragraph
 * separator characters and cap the length.
 */
internal fun sanitizeRemoteText(text: String?): String {
    if (text.isNullOrEmpty()) return ""
    val cleaned = text.take(MAX_REMOTE_INPUT).filter { ch ->
        val type = Character.getType(ch)
        type != Character.CONTROL.toInt() && type != Character.FORMAT.toInt() &&
            type != Character.LINE_SEPARATOR.toInt() && type != Character.PARAGRAPH_SEPARATOR.toInt()
    }
    return if (cleaned.length <= MAX_REMOTE_TEXT) cleaned else cleaned.take(MAX_REMOTE_TEXT - ELLIPSIS.length) + ELLIPSIS
}

private const val MAX_REMOTE_TEXT = 200
private const val MAX_REMOTE_INPUT = 4096
private const val ELLIPSIS = "..."
private const val MAX_CAUSE_DEPTH = 16
