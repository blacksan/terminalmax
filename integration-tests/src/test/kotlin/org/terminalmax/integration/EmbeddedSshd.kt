// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.integration

import java.io.InputStream
import java.io.OutputStream
import java.security.KeyPairGenerator
import kotlin.concurrent.thread
import org.apache.sshd.common.keyprovider.KeyPairProvider
import org.apache.sshd.server.Environment
import org.apache.sshd.server.ExitCallback
import org.apache.sshd.server.ServerBuilder
import org.apache.sshd.server.SshServer
import org.apache.sshd.server.auth.password.PasswordAuthenticator
import org.apache.sshd.server.channel.ChannelSession
import org.apache.sshd.server.command.Command
import org.apache.sshd.server.command.CommandFactory
import org.apache.sshd.server.shell.ShellFactory

const val E2E_USER = "tester"
const val E2E_PASSWORD = "s3cret"

/**
 * Embedded Apache MINA SSHD bound to [host] (the kernel WireGuard peer address) on an
 * OS-assigned port, with in-process commands: "echo x" prints x, the shell answers "got:<line>".
 */
class EmbeddedSshd(host: String) : AutoCloseable {
    private val server: SshServer = ServerBuilder.builder().build()

    val port: Int get() = server.port

    init {
        server.setHost(host)
        server.setPort(0)
        val hostKey = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        server.setKeyPairProvider(KeyPairProvider.wrap(hostKey))
        server.setPasswordAuthenticator(
            PasswordAuthenticator { user, password, _ -> user == E2E_USER && password == E2E_PASSWORD },
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

private class EchoExecCommand(private val command: String) : BaseCommand() {
    override fun start(channel: ChannelSession, env: Environment) {
        thread(isDaemon = true, name = "e2e-exec") {
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

private class LineEchoShell : BaseCommand() {
    override fun start(channel: ChannelSession, env: Environment) {
        thread(isDaemon = true, name = "e2e-shell") {
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
