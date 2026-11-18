// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout

class SshjTransportIntegrationTest {
    private val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private lateinit var sshd: TestSshd
    private val transport = SshjTransport()

    /** Test-only verifier that records what it was asked and accepts. */
    private class RecordingVerifier(private val accept: Boolean) : HostKeyVerifier {
        var host: String? = null
        var port: Int? = null
        var keyType: String? = null
        var fingerprint: String? = null
        var keyBlob: ByteArray? = null

        override fun verify(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): Boolean {
            this.host = host
            this.port = port
            this.keyType = keyType
            this.fingerprint = fingerprintSha256
            this.keyBlob = key
            return accept
        }
    }

    @BeforeTest
    fun setUp() {
        sshd = TestSshd(rsa.public as RSAPublicKey)
    }

    @AfterTest
    fun tearDown() {
        sshd.close()
    }

    private fun localTarget() = SshTarget("127.0.0.1", sshd.port, TEST_USER)

    private fun <T> blocking(block: suspend () -> T): T = runBlocking { withTimeout(30_000) { block() } }

    @Test
    fun passwordAuthAndExec(): Unit = blocking {
        val verifier = RecordingVerifier(true)
        val session = transport.connect(localTarget(), SshAuth.Password(TEST_PASSWORD.toCharArray()), verifier)
        try {
            val result = session.exec("echo hello")
            assertEquals("hello\n", String(result.stdout))
            assertEquals(0, result.exitCode)
            assertEquals("127.0.0.1", verifier.host)
            assertEquals(sshd.port, verifier.port)
            val fingerprint = verifier.fingerprint!!
            assertTrue(fingerprint.startsWith("SHA256:"))
            assertFalse(fingerprint.contains("="))
            assertTrue(verifier.keyType!!.isNotEmpty())
            assertTrue(verifier.keyBlob!!.isNotEmpty())
        } finally {
            session.close()
        }
    }

    @Test
    fun execReportsNonZeroExitAndStderr(): Unit = blocking {
        val session = transport.connect(
            localTarget(), SshAuth.Password(TEST_PASSWORD.toCharArray()), RecordingVerifier(true),
        )
        try {
            val result = session.exec("nope")
            assertEquals(127, result.exitCode)
            assertEquals("unknown command\n", String(result.stderr))
        } finally {
            session.close()
        }
    }

    @Test
    fun publicKeyAuth(): Unit = blocking {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(rsa.private.encoded)
        val pem = "-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n"
        val session = transport.connect(localTarget(), SshAuth.PrivateKey(pem), RecordingVerifier(true))
        try {
            assertEquals("hello\n", String(session.exec("echo hello").stdout))
        } finally {
            session.close()
        }
    }

    @Test
    fun shellRoundTripAndResize(): Unit = blocking {
        val session = transport.connect(
            localTarget(), SshAuth.Password(TEST_PASSWORD.toCharArray()), RecordingVerifier(true),
        )
        try {
            val shell = session.openShell(PtyRequest())
            try {
                shell.write("ping\n".toByteArray())
                shell.resize(120, 40)
                val seen = StringBuilder()
                shell.output.first { chunk ->
                    seen.append(String(chunk))
                    seen.contains("got:ping")
                }
                assertTrue(seen.contains("got:ping"))
            } finally {
                shell.close()
            }
        } finally {
            session.close()
        }
    }

    @Test
    fun rejectedHostKeyFailsAndVerifierSeesRealTarget(): Unit = blocking {
        val token = ByteArray(32) { it.toByte() }
        TokenProxy(token, sshd.port).use { proxy ->
            val verifier = RecordingVerifier(false)
            val target = SshTarget("router.test.invalid", 2222, TEST_USER)
            assertFailsWith<SshException> {
                transport.connect(
                    target, SshAuth.Password(TEST_PASSWORD.toCharArray()), verifier,
                    via = LoopbackPreamble(proxy.port, token),
                )
            }
            assertEquals("router.test.invalid", verifier.host)
            assertEquals(2222, verifier.port)
        }
    }

    @Test
    fun loopbackPreambleSendsTokenFirst(): Unit = blocking {
        val token = ByteArray(32) { (it * 7 + 1).toByte() }
        TokenProxy(token, sshd.port).use { proxy ->
            val verifier = RecordingVerifier(true)
            val target = SshTarget("router.test.invalid", 2222, TEST_USER)
            val session = transport.connect(
                target, SshAuth.Password(TEST_PASSWORD.toCharArray()), verifier,
                via = LoopbackPreamble(proxy.port, token),
            )
            try {
                assertEquals("hello\n", String(session.exec("echo hello").stdout))
            } finally {
                session.close()
            }
            assertEquals(1, proxy.tokensSeen.size)
            assertContentEquals(token, proxy.tokensSeen.first())
            assertEquals("router.test.invalid", verifier.host)
            assertEquals(2222, verifier.port)
        }
    }

    @Test
    fun loopbackPreambleWithWrongTokenFails(): Unit = blocking {
        val expected = ByteArray(32) { 1 }
        val wrong = ByteArray(32) { 2 }
        TokenProxy(expected, sshd.port).use { proxy ->
            val target = SshTarget("router.test.invalid", 2222, TEST_USER)
            val e = assertFailsWith<SshException> {
                transport.connect(
                    target, SshAuth.Password(TEST_PASSWORD.toCharArray()), RecordingVerifier(true),
                    via = LoopbackPreamble(proxy.port, wrong),
                )
            }
            assertEquals(1, proxy.tokensSeen.size)
            assertContentEquals(wrong, proxy.tokensSeen.first())
            assertFalse(e.message.orEmpty().contains(wrong.joinToString("")))
        }
    }

    @Test
    fun wrongPasswordFailsWithoutLeakingIt(): Unit = blocking {
        val bad = "wrong-password-xyz"
        val e = assertFailsWith<SshException> {
            transport.connect(localTarget(), SshAuth.Password(bad.toCharArray()), RecordingVerifier(true))
        }
        assertFalse(e.message.orEmpty().contains(bad))
    }
}
