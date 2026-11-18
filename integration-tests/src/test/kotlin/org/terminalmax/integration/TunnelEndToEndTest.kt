// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.integration

import java.io.File
import java.net.InetAddress
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.terminalmax.core.ssh.HostKeyDecision
import org.terminalmax.core.ssh.HostKeyVerifier
import org.terminalmax.core.ssh.LoopbackPreamble
import org.terminalmax.core.ssh.SshAuth
import org.terminalmax.core.ssh.SshSession
import org.terminalmax.core.ssh.SshTarget
import org.terminalmax.core.ssh.SshjTransport
import org.terminalmax.core.wireguard.LoopbackForward
import org.terminalmax.core.wireguard.WireGuardBackend
import org.terminalmax.core.wireguard.WireGuardException
import org.terminalmax.core.wireguard.WireGuardTunnel
import org.terminalmax.core.wireguard.createWireGuardBackend

/**
 * Core path of the product against a real kernel WireGuard peer:
 * SSH client -> loopback forwarder (token) -> wgbridge userspace tunnel -> kernel wireguard -> sshd.
 *
 * Runs only with TMX_E2E=1 (otherwise every test returns at once). Environment:
 *  - TMX_WG_CONFIG:    path of the client wg-quick config
 *  - TMX_WGBRIDGE_LIB: absolute path of libwgbridge.so
 *  - TMX_WG_SERVER_IP: address of the kernel peer (default 10.99.0.1)
 *  - TMX_WG_CLIENT_IP: tunnel address of the client config (default 10.99.0.2)
 *
 * The library is loaded through `terminalmax.wgbridge.path`, which the desktop loader honours only
 * together with `-Dterminalmax.dev=true`; Gradle sets that for this module's test task.
 */
class TunnelEndToEndTest {
    private val enabled = System.getenv("TMX_E2E") == "1"
    private val serverIp = System.getenv("TMX_WG_SERVER_IP") ?: "10.99.0.1"
    private val clientIp = System.getenv("TMX_WG_CLIENT_IP") ?: "10.99.0.2"

    private var sshd: EmbeddedSshd? = null
    private var tunnel: WireGuardTunnel? = null
    private val transport = SshjTransport()

    /** A name that never resolves: proves the transport does not use it for the connection. */
    private val fakeHost = "router.e2e.invalid"

    private class RecordingVerifier : HostKeyVerifier {
        val seen = CopyOnWriteArrayList<Pair<String, Int>>()

        override fun check(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): HostKeyDecision {
            seen.add(host to port)
            return HostKeyDecision.Trusted
        }
    }

    private fun requireEnv(name: String): String =
        System.getenv(name)?.takeIf { it.isNotEmpty() } ?: fail("TMX_E2E=1 but environment variable $name is not set")

    @BeforeTest
    fun setUp() {
        if (!enabled) return
        val libPath = requireEnv("TMX_WGBRIDGE_LIB")
        val configPath = requireEnv("TMX_WG_CONFIG")
        assertTrue(File(libPath).isFile, "native library not found: $libPath")
        assertTrue(File(configPath).isFile, "wireguard client config not found: $configPath")
        assertEquals(
            "true",
            System.getProperty("terminalmax.dev"),
            "the test JVM must run with -Dterminalmax.dev=true (set by integration-tests/build.gradle.kts)",
        )
        System.setProperty("terminalmax.wgbridge.path", libPath)

        sshd = EmbeddedSshd(serverIp)
        val backend: WireGuardBackend = createWireGuardBackend()
        println("wgbridge version: ${backend.version()}")
        // start() zero-fills the array it is given.
        tunnel = backend.start(File(configPath).readBytes())
    }

    @AfterTest
    fun tearDown() {
        runCatching { tunnel?.close() }
        runCatching { sshd?.close() }
    }

    private fun <T> blocking(block: suspend CoroutineScope.() -> T): T? {
        if (!enabled) return null
        return runBlocking(Dispatchers.IO) { withTimeout(120_000) { block() } }
    }

    private suspend fun connect(forward: LoopbackForward, verifier: HostKeyVerifier): SshSession {
        val token = forward.token
        try {
            return transport.connect(
                SshTarget(fakeHost, sshd!!.port, E2E_USER),
                SshAuth.Password(E2E_PASSWORD.toCharArray()),
                verifier,
                via = LoopbackPreamble(forward.port, token),
            )
        } finally {
            token.fill(0)
        }
    }

    @Test
    fun sshExecAndShellOverTunnel() {
        blocking {
            val t = tunnel!!
            val verifier = RecordingVerifier()
            val forward = t.openForward(serverIp, sshd!!.port)
            val session = connect(forward, verifier)
            try {
                assertTrue(verifier.seen.isNotEmpty(), "the host-key verifier was never asked")
                assertTrue(
                    verifier.seen.all { it == fakeHost to sshd!!.port },
                    "host key must be checked against the real target, saw ${verifier.seen}",
                )

                val result = session.exec("echo hello-e2e")
                assertEquals(0, result.exitCode)
                assertEquals("hello-e2e\n", String(result.stdout))

                val shell = session.openShell()
                try {
                    shell.write("ping\n".toByteArray())
                    val seen = StringBuilder()
                    shell.output.first { chunk ->
                        seen.append(String(chunk))
                        seen.contains("got:ping")
                    }
                } finally {
                    shell.close()
                }
            } finally {
                session.close()
            }

            // The server must have seen the tunnel address as the client, not 127.0.0.1: only traffic
            // that really crossed wireguard-go and the kernel peer carries it as its source.
            val peers = sshd!!.clientAddresses
            assertTrue(peers.isNotEmpty(), "the embedded sshd accepted no connection")
            assertTrue(peers.all { it == clientIp }, "sshd saw client addresses $peers, expected only $clientIp")

            val stats = t.stats()
            assertNotNull(stats.lastHandshakeEpochSeconds, "no WireGuard handshake completed: $stats")
            assertTrue(stats.rxBytes > 0, "no bytes received through the tunnel: $stats")
            assertTrue(stats.txBytes > 0, "no bytes sent through the tunnel: $stats")
        }
    }

    @Test
    fun wrongTokenGetsNoBannerAndIsClosed() {
        blocking {
            val t = tunnel!!
            val forward = t.openForward(serverIp, sshd!!.port)
            val good = forward.token
            val wrong = ByteArray(good.size) { (good[it] + 1).toByte() }
            good.fill(0)

            Socket(InetAddress.getByName("127.0.0.1"), forward.port).use { socket ->
                socket.soTimeout = 15_000
                socket.getOutputStream().apply {
                    write(wrong)
                    flush()
                }
                // The SSH server speaks first, so any byte here would be a banner. Expect EOF or a reset.
                val first = try {
                    socket.getInputStream().read()
                } catch (_: SocketException) {
                    -1
                }
                assertEquals(-1, first, "a wrong token must not reach the SSH server (got a byte)")
            }

            // The failed authentication is reported through stats (may take a moment).
            var error: String? = t.stats().lastForwardError
            var attempts = 0
            while (error == null && attempts < 10) {
                Thread.sleep(500)
                error = t.stats().lastForwardError
                attempts++
            }
            assertTrue(error?.contains("authentication") == true, "expected a forward authentication error, got: $error")

            // The tunnel itself is unharmed: a fresh forward with the right token works.
            val again = t.openForward(serverIp, sshd!!.port)
            val session = connect(again, RecordingVerifier())
            try {
                assertEquals("still-up\n", String(session.exec("echo still-up").stdout))
            } finally {
                session.close()
            }
        }
    }

    @Test
    fun rebindThenNewForwardStillWorks() {
        blocking {
            val t = tunnel!!
            val first = connect(t.openForward(serverIp, sshd!!.port), RecordingVerifier())
            try {
                assertEquals("one\n", String(first.exec("echo one").stdout))
            } finally {
                first.close()
            }

            t.rebind()

            val second = connect(t.openForward(serverIp, sshd!!.port), RecordingVerifier())
            try {
                assertEquals("two\n", String(second.exec("echo two").stdout))
            } finally {
                second.close()
            }
        }
    }

    @Test
    fun closeIsIdempotent() {
        blocking {
            val t = tunnel!!
            t.close()
            t.close()
            assertFailsWith<WireGuardException> { t.stats() }
            assertFailsWith<WireGuardException> { t.openForward(serverIp, sshd!!.port) }
        }
    }
}
