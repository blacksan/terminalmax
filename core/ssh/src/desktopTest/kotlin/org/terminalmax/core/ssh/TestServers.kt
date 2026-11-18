// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.apache.sshd.common.NamedFactory
import org.apache.sshd.common.cipher.BuiltinCiphers
import org.apache.sshd.common.cipher.Cipher
import org.apache.sshd.common.kex.BuiltinDHFactories
import org.apache.sshd.common.kex.KeyExchangeFactory
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.common.mac.BuiltinMacs
import org.apache.sshd.common.mac.Mac
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.ServerBuilder
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.server.shell.ShellFactory

const val TEST_USER = "tester"
const val TEST_PASSWORD = "s3cret"

fun newRsaKeyPair(): KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

/**
 * Embedded Apache MINA SSHD on 127.0.0.1 with in-process commands (no OS processes).
 *
 * It listens on an OS-assigned port (port 0; MINA's start() stores the bound port, so [port] is
 * valid once the constructor returns), which avoids the close-then-rebind race of a "free port" probe.
 *
 * @param hostKey the server host key; pass the same key pair to get the same host key again.
 * @param legacyCryptoOnly restrict the server to aes128-cbc + hmac-sha1 + diffie-hellman-group14-sha1.
 */
class TestSshd(
    private val authorizedRsaKey: RSAPublicKey,
    val hostKey: KeyPair = newRsaKeyPair(),
    legacyCryptoOnly: Boolean = false,
) : AutoCloseable {
    private val server: SshServer

    val port: Int get() = server.port

    init {
        val builder = ServerBuilder.builder()
        if (legacyCryptoOnly) {
            @Suppress("DEPRECATION") // MINA marks group14-sha1 deprecated; that is the point of this server.
            val kex = ServerBuilder.DH2KEX.apply(BuiltinDHFactories.dhg14)
            builder.cipherFactories(listOf<NamedFactory<Cipher>>(BuiltinCiphers.aes128cbc))
            builder.macFactories(listOf<NamedFactory<Mac>>(BuiltinMacs.hmacsha1))
            builder.keyExchangeFactories(listOf<KeyExchangeFactory>(kex))
        }
        server = builder.build()
        server.setHost("127.0.0.1")
        server.setPort(0)
        server.setKeyPairProvider(KeyPairProvider.wrap(hostKey))
        server.setPasswordAuthenticator(
            PasswordAuthenticator { user, password, _ -> user == TEST_USER && password == TEST_PASSWORD },
        )
        server.setPublickeyAuthenticator(
            PublickeyAuthenticator { user, key, _ ->
                user == TEST_USER && key is RSAPublicKey && key.modulus == authorizedRsaKey.modulus &&
                    key.publicExponent == authorizedRsaKey.publicExponent
            },
        )
        server.setCommandFactory(CommandFactory { _, command -> EchoExecCommand(command) })
        server.setShellFactory(ShellFactory { _ -> LineEchoShell() })
        server.start()
        check(server.port > 0) { "MINA did not report the bound port" }
    }

    override fun close() {
        runCatching { server.stop(true) }
    }
}

/** Accepts one TCP connection and never says anything; records when the client closes its end. */
class BlackholeServer : AutoCloseable {
    private val server = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
    val port: Int = server.localPort
    private val accepted = CountDownLatch(1)
    private val clientClosed = CountDownLatch(1)

    init {
        thread(isDaemon = true, name = "test-blackhole") {
            try {
                server.accept().use { socket ->
                    accepted.countDown()
                    try {
                        val input = socket.getInputStream()
                        val buffer = ByteArray(256)
                        while (input.read(buffer) >= 0) {
                            // swallow the client's identification string, never answer
                        }
                    } catch (_: Exception) {
                        // reset counts as closed
                    }
                    clientClosed.countDown()
                }
            } catch (_: Exception) {
                // server closed
            }
        }
    }

    fun awaitAccepted(timeoutMillis: Long): Boolean = accepted.await(timeoutMillis, TimeUnit.MILLISECONDS)

    fun awaitClientClosed(timeoutMillis: Long): Boolean = clientClosed.await(timeoutMillis, TimeUnit.MILLISECONDS)

    override fun close() {
        runCatching { server.close() }
    }
}

private abstract class BaseCommand : Command {
    protected var input: InputStream? = null
    protected var output: OutputStream? = null
    protected var error: OutputStream? = null
    protected var callback: ExitCallback? = null

    override fun setInputStream(`in`: InputStream) {
        input = `in`
    }

    override fun setOutputStream(out: OutputStream) {
        output = out
    }

    override fun setErrorStream(err: OutputStream) {
        error = err
    }

    override fun setExitCallback(callback: ExitCallback) {
        this.callback = callback
    }

    override fun destroy(channel: ChannelSession) {}
}

/** "echo foo bar" prints "foo bar\n" and exits 0; anything else exits 127. */
private class EchoExecCommand(private val command: String) : BaseCommand() {
    override fun start(channel: ChannelSession, env: Environment) {
        thread(isDaemon = true, name = "test-exec") {
            val out = output!!
            if (command.startsWith("echo ")) {
                out.write((command.removePrefix("echo ") + "\n").toByteArray())
                out.flush()
                callback!!.onExit(0)
            } else if (command == "flood") {
                // 2 MiB of stdout, more than the client's 1 MiB cap.
                try {
                    val chunk = ByteArray(64 * 1024) { 'x'.code.toByte() }
                    repeat(32) { out.write(chunk) }
                    out.flush()
                } catch (_: Exception) {
                    // the client gave up and closed the channel
                }
                callback!!.onExit(0)
            } else if (command == "hang") {
                // Never produces output and never exits on its own.
                try {
                    Thread.sleep(60_000)
                } catch (_: InterruptedException) {
                    // test finished
                }
                callback!!.onExit(0)
            } else {
                error!!.write("unknown command\n".toByteArray())
                error!!.flush()
                callback!!.onExit(127)
            }
        }
    }
}

/** Replies "got:<line>\n" for each input line; exits 0 when the client closes the channel. */
private class LineEchoShell : BaseCommand() {
    override fun start(channel: ChannelSession, env: Environment) {
        thread(isDaemon = true, name = "test-shell") {
            val stream = input!!
            val out = output!!
            val line = StringBuilder()
            try {
                while (true) {
                    val b = stream.read()
                    if (b < 0) break
                    if (b == '\n'.code) {
                        out.write(("got:$line\n").toByteArray())
                        out.flush()
                        line.setLength(0)
                    } else if (b != '\r'.code) {
                        line.append(b.toChar())
                    }
                }
            } catch (_: Exception) {
                // channel closed
            }
            callback!!.onExit(0)
        }
    }
}

/**
 * Loopback proxy that mimics the in-app forwarder: reads a 32-byte token first, compares it,
 * and only then pipes bytes to the SSHD port.
 */
class TokenProxy(private val expectedToken: ByteArray, private val upstreamPort: Int) : AutoCloseable {
    private val server = ServerSocket(0, 10, InetAddress.getByName("127.0.0.1"))
    val port: Int = server.localPort

    /** When set, bytes are still read in both directions but no longer forwarded (a dead path). */
    @Volatile
    var stalled = false

    /** Every token received, in order of arrival. */
    val tokensSeen = CopyOnWriteArrayList<ByteArray>()

    init {
        thread(isDaemon = true, name = "test-proxy-accept") {
            while (!server.isClosed) {
                val client = try {
                    server.accept()
                } catch (_: Exception) {
                    break
                }
                thread(isDaemon = true, name = "test-proxy-conn") { handle(client) }
            }
        }
    }

    private fun handle(client: Socket) {
        try {
            val token = client.getInputStream().readNBytes(expectedToken.size)
            tokensSeen.add(token)
            if (!MessageDigest.isEqual(token, expectedToken)) {
                client.close()
                return
            }
            val upstream = Socket(InetAddress.getByName("127.0.0.1"), upstreamPort)
            pipe(client.getInputStream(), upstream.getOutputStream(), client, upstream)
            pipe(upstream.getInputStream(), client.getOutputStream(), client, upstream)
        } catch (_: Exception) {
            runCatching { client.close() }
        }
    }

    private fun pipe(from: InputStream, to: OutputStream, a: Socket, b: Socket) {
        thread(isDaemon = true, name = "test-proxy-pipe") {
            try {
                val buf = ByteArray(8192)
                while (true) {
                    val n = from.read(buf)
                    if (n < 0) break
                    if (!stalled) {
                        to.write(buf, 0, n)
                        to.flush()
                    }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { a.close() }
                runCatching { b.close() }
            }
        }
    }

    override fun close() {
        runCatching { server.close() }
    }
}
