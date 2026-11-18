// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.concurrent.thread
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider
import org.apache.sshd.server.shell.ShellFactory

const val TEST_USER = "tester"
const val TEST_PASSWORD = "s3cret"

/** Embedded Apache MINA SSHD on 127.0.0.1 with in-process commands (no OS processes). */
class TestSshd(private val authorizedRsaKey: RSAPublicKey) : AutoCloseable {
    private val dir: Path = Files.createTempDirectory("terminalmax-sshd")
    private val server: SshServer = SshServer.setUpDefaultServer()
    val port: Int = freePort()

    init {
        server.setHost("127.0.0.1")
        server.setPort(port)
        // The file must not exist yet; the provider generates the host key there.
        server.setKeyPairProvider(SimpleGeneratorHostKeyProvider(dir.resolve("hostkey.ser")))
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
    }

    override fun close() {
        runCatching { server.stop(true) }
        runCatching { dir.toFile().deleteRecursively() }
    }
}

fun freePort(): Int = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }

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
                    to.write(buf, 0, n)
                    to.flush()
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
