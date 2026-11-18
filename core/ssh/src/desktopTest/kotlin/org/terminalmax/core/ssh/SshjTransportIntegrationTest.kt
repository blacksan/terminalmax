// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.ssh

import java.security.KeyPair
import java.security.MessageDigest
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.concurrent.atomic.AtomicReference
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.apache.sshd.common.config.keys.KeyUtils
import org.apache.sshd.common.digest.BuiltinDigests
import org.apache.sshd.common.util.buffer.ByteArrayBuffer

class SshjTransportIntegrationTest {
    private val rsa = newRsaKeyPair()
    private lateinit var sshd: TestSshd
    private val transport = SshjTransport()

    /** Test-only verifier that records what it was asked and returns a fixed decision. */
    private class RecordingVerifier(
        private val decision: HostKeyDecision = HostKeyDecision.Trusted,
        private val known: List<String> = emptyList(),
    ) : HostKeyVerifier {
        var host: String? = null
        var port: Int? = null
        var keyType: String? = null
        var fingerprint: String? = null
        var keyBlob: ByteArray? = null
        var knownTypesAskedFor: Pair<String, Int>? = null

        override fun check(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): HostKeyDecision {
            this.host = host
            this.port = port
            this.keyType = keyType
            this.fingerprint = fingerprintSha256
            this.keyBlob = key
            return decision
        }

        override fun knownKeyTypes(host: String, port: Int): List<String> {
            knownTypesAskedFor = host to port
            return known
        }
    }

    /** Trusts the first key it sees (like a user accepting a TOFU prompt) and reports any other as a mismatch. */
    private class RememberingVerifier : HostKeyVerifier {
        private var remembered: ByteArray? = null

        override fun check(host: String, port: Int, keyType: String, fingerprintSha256: String, key: ByteArray): HostKeyDecision {
            val first = remembered
            if (first == null) {
                remembered = key.copyOf()
                return HostKeyDecision.Trusted
            }
            return if (MessageDigest.isEqual(first, key)) HostKeyDecision.Trusted else HostKeyDecision.Mismatch
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

    private fun password() = SshAuth.Password(TEST_PASSWORD.toCharArray())

    private fun <T> blocking(block: suspend CoroutineScope.() -> T): T = runBlocking { withTimeout(30_000) { block() } }

    private fun minaFingerprint(key: KeyPair): String = KeyUtils.getFingerPrint(BuiltinDigests.sha256, key.public)

    private fun minaBlob(key: KeyPair): ByteArray = ByteArrayBuffer().apply { putRawPublicKey(key.public) }.compactData

    private fun pemOf(key: KeyPair): Pair<String, String> {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(key.private.encoded)
        return "-----BEGIN PRIVATE KEY-----\n$b64\n-----END PRIVATE KEY-----\n" to b64
    }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    // ---- basics --------------------------------------------------------------------------------

    @Test
    fun passwordAuthAndExec(): Unit = blocking {
        val verifier = RecordingVerifier()
        val session = transport.connect(localTarget(), password(), verifier)
        try {
            val result = session.exec("echo hello")
            assertEquals("hello\n", String(result.stdout))
            assertEquals(0, result.exitCode)
            assertEquals("127.0.0.1", verifier.host)
            assertEquals(sshd.port, verifier.port)
            assertEquals("ssh-rsa", verifier.keyType)
            // Fingerprint and blob must be what the server itself computes for its host key.
            assertEquals(minaFingerprint(sshd.hostKey), verifier.fingerprint)
            assertContentEquals(minaBlob(sshd.hostKey), verifier.keyBlob)
            assertFalse(verifier.fingerprint!!.contains("="))
            // The default (Modern) profile against a modern server.
            assertFalse(session.usesLegacyCrypto)
            assertTrue(session.negotiated.kex.isNotEmpty())
        } finally {
            session.close()
        }
    }

    @Test
    fun execReportsNonZeroExitAndStderr(): Unit = blocking {
        val session = transport.connect(localTarget(), password(), RecordingVerifier())
        try {
            val result = session.exec("nope")
            assertEquals(127, result.exitCode)
            assertEquals("unknown command\n", String(result.stderr))
        } finally {
            session.close()
        }
    }

    @Test
    fun execOutputIsCappedAtOneMiB(): Unit = blocking {
        val session = transport.connect(localTarget(), password(), RecordingVerifier())
        try {
            val e = assertFailsWith<SshException.Protocol> { session.exec("flood") }
            assertTrue(e.message.orEmpty().contains("output too large"), e.message)
            // The session itself is still fine.
            assertEquals("hello\n", String(session.exec("echo hello").stdout))
        } finally {
            session.close()
        }
    }

    @Test
    fun execIsCancellable(): Unit = blocking {
        val session = transport.connect(localTarget(), password(), RecordingVerifier())
        try {
            val job = launch(Dispatchers.Default) { session.exec("hang") }
            delay(500)
            withTimeout(5_000) { job.cancelAndJoin() }
            assertTrue(job.isCancelled)
            assertEquals("hello\n", String(session.exec("echo hello").stdout))
        } finally {
            session.close()
        }
    }

    @Test
    fun publicKeyAuth(): Unit = blocking {
        val session = transport.connect(localTarget(), SshAuth.PrivateKey(pemOf(rsa).first), RecordingVerifier())
        try {
            assertEquals("hello\n", String(session.exec("echo hello").stdout))
        } finally {
            session.close()
        }
    }

    @Test
    fun shellRoundTripAndResize(): Unit = blocking {
        val session = transport.connect(localTarget(), password(), RecordingVerifier())
        try {
            val shell = session.openShell(PtyRequest())
            try {
                shell.write("ping\n".toByteArray())
                shell.resize(120, 40)
                assertFailsWith<IllegalArgumentException> { shell.resize(0, 40) }
                assertFailsWith<IllegalArgumentException> { shell.resize(1001, 40) }
                assertFailsWith<IllegalArgumentException> { shell.resize(80, 0) }
                assertFailsWith<IllegalArgumentException> { shell.resize(80, 501) }
                assertFailsWith<IllegalArgumentException> { shell.resize(-1, -1) }
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

    // ---- shell output flow ---------------------------------------------------------------------

    @Test
    fun cancellingOutputCollectionRaisesOnlyCancellation(): Unit = blocking {
        val session = transport.connect(localTarget(), password(), RecordingVerifier())
        try {
            val shell = session.openShell(PtyRequest())
            try {
                val thrown = AtomicReference<Throwable?>(null)
                val ready = CompletableDeferred<Unit>()
                val collector = launch(Dispatchers.IO) {
                    try {
                        shell.output.collect { chunk -> if (String(chunk).contains("got:ping")) ready.complete(Unit) }
                    } catch (e: Throwable) {
                        thrown.set(e)
                        throw e
                    }
                }
                shell.write("ping\n".toByteArray())
                ready.await()
                // The collector is now blocked in read() on an idle shell: the normal state.
                delay(200)
                withTimeout(5_000) { collector.cancelAndJoin() }
                val e = thrown.get()
                assertTrue(e == null || e is CancellationException, "unexpected exception: $e")
                // The interrupted read must not have damaged the connection.
                assertEquals("hello\n", String(session.exec("echo hello").stdout))
            } finally {
                shell.close()
            }
        } finally {
            session.close()
        }
    }

    @Test
    fun secondOutputCollectorFails(): Unit = blocking {
        val session = transport.connect(localTarget(), password(), RecordingVerifier())
        try {
            val shell = session.openShell(PtyRequest())
            try {
                shell.write("ping\n".toByteArray())
                shell.output.first { String(it).contains("got:ping") }
                assertFailsWith<IllegalStateException> { shell.output.collect { } }
            } finally {
                shell.close()
            }
        } finally {
            session.close()
        }
    }

    // ---- host keys -----------------------------------------------------------------------------

    @Test
    fun unknownHostKeyFailsWithTypeAndRealTarget(): Unit = blocking {
        val token = ByteArray(32) { it.toByte() }
        TokenProxy(token, sshd.port).use { proxy ->
            val verifier = RecordingVerifier(HostKeyDecision.Unknown)
            val target = SshTarget("router.test.invalid", 2222, TEST_USER)
            val e = assertFailsWith<SshException.HostKeyUnknown> {
                transport.connect(target, password(), verifier, via = LoopbackPreamble(proxy.port, token))
            }
            assertEquals("router.test.invalid", verifier.host)
            assertEquals(2222, verifier.port)
            assertEquals("router.test.invalid", e.host)
            assertEquals(2222, e.port)
            assertEquals("ssh-rsa", e.keyType)
            assertEquals(minaFingerprint(sshd.hostKey), e.fingerprintSha256)
            assertContentEquals(minaBlob(sshd.hostKey), e.key)
        }
    }

    @Test
    fun mismatchDecisionFailsWithHostKeyChanged(): Unit = blocking {
        val e = assertFailsWith<SshException.HostKeyChanged> {
            transport.connect(localTarget(), password(), RecordingVerifier(HostKeyDecision.Mismatch))
        }
        assertEquals("127.0.0.1", e.host)
        assertEquals(sshd.port, e.port)
        assertEquals(minaFingerprint(sshd.hostKey), e.fingerprintSha256)
        assertContentEquals(minaBlob(sshd.hostKey), e.key)
    }

    @Test
    fun hostKeyChangeBetweenConnectsIsDetected(): Unit = blocking {
        val verifier = RememberingVerifier()
        val first = transport.connect(localTarget(), password(), verifier)
        first.close()

        val otherKey = newRsaKeyPair()
        TestSshd(rsa.public as RSAPublicKey, hostKey = otherKey).use { other ->
            val e = assertFailsWith<SshException.HostKeyChanged> {
                transport.connect(SshTarget("127.0.0.1", other.port, TEST_USER), password(), verifier)
            }
            assertEquals(minaFingerprint(otherKey), e.fingerprintSha256)
            assertNotEquals(minaFingerprint(sshd.hostKey), e.fingerprintSha256)
        }

        // The original server is still accepted.
        val again = transport.connect(localTarget(), password(), verifier)
        again.close()
    }

    @Test
    fun verifierExceptionIsReportedAsProtocolWithCause(): Unit = blocking {
        val boom = IllegalStateException("verifier boom")
        val e = assertFailsWith<SshException.Protocol> {
            transport.connect(localTarget(), password(), HostKeyVerifier { _, _, _, _, _ -> throw boom })
        }
        // Coroutine stack-trace recovery may wrap the exception in a copy, so walk the cause chain.
        assertTrue(generateSequence<Throwable>(e) { it.cause }.any { it === boom }, "cause chain was ${e.cause}")
        assertFalse(e.message.orEmpty().contains("rejected"))
    }

    @Test
    fun knownKeyTypesAreAskedForWithTheRealTarget(): Unit = blocking {
        val verifier = RecordingVerifier(known = listOf("ssh-rsa"))
        transport.connect(localTarget(), password(), verifier).close()
        assertEquals("127.0.0.1" to sshd.port, verifier.knownTypesAskedFor)
    }

    // ---- loopback preamble ---------------------------------------------------------------------

    @Test
    fun loopbackPreambleSendsTokenFirst(): Unit = blocking {
        val token = ByteArray(32) { (it * 7 + 1).toByte() }
        TokenProxy(token, sshd.port).use { proxy ->
            val verifier = RecordingVerifier()
            val target = SshTarget("router.test.invalid", 2222, TEST_USER)
            val session = transport.connect(target, password(), verifier, via = LoopbackPreamble(proxy.port, token))
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
    fun loopbackPreambleWithWrongTokenFailsWithoutLeakingIt(): Unit = blocking {
        val expected = ByteArray(32) { 1 }
        val wrong = ByteArray(32) { (0xA0 + it).toByte() }
        TokenProxy(expected, sshd.port).use { proxy ->
            val target = SshTarget("router.test.invalid", 2222, TEST_USER)
            val e = assertFailsWith<SshException> {
                transport.connect(target, password(), RecordingVerifier(), via = LoopbackPreamble(proxy.port, wrong))
            }
            assertEquals(1, proxy.tokensSeen.size)
            assertContentEquals(wrong, proxy.tokensSeen.first())
            val trace = e.stackTraceToString()
            assertFalse(trace.contains(hex(wrong)), "token (hex) in stack trace")
            assertFalse(trace.contains(Base64.getEncoder().encodeToString(wrong)), "token (base64) in stack trace")
            assertFalse(trace.contains(wrong.joinToString(", ")), "token (array form) in stack trace")
        }
    }

    @Test
    fun loopbackPreambleValidatesAndCopiesToken() {
        assertFailsWith<IllegalArgumentException> { LoopbackPreamble(1234, ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { LoopbackPreamble(1234, ByteArray(33)) }
        assertFailsWith<IllegalArgumentException> { LoopbackPreamble(0, ByteArray(32)) }
        val original = ByteArray(32) { 9 }
        val preamble = LoopbackPreamble(1234, original)
        original.fill(0) // the caller wipes its array
        assertContentEquals(ByteArray(32) { 9 }, preamble.token)
        assertFalse(preamble.toString().contains("9"))
    }

    // ---- secrets -------------------------------------------------------------------------------

    @Test
    fun wrongPasswordFailsWithAuthFailedWithoutLeakingIt(): Unit = blocking {
        val bad = "wrong-password-xyz"
        val e = assertFailsWith<SshException.AuthFailed> {
            transport.connect(localTarget(), SshAuth.Password(bad.toCharArray()), RecordingVerifier())
        }
        assertFalse(e.stackTraceToString().contains(bad))
    }

    @Test
    fun unauthorizedKeyFailsWithAuthFailedWithoutLeakingIt(): Unit = blocking {
        val (pem, body) = pemOf(newRsaKeyPair())
        val e = assertFailsWith<SshException.AuthFailed> {
            transport.connect(localTarget(), SshAuth.PrivateKey(pem), RecordingVerifier())
        }
        val trace = e.stackTraceToString()
        assertFalse(trace.contains(body.lines().first()), "PEM body in stack trace")
        assertFalse(trace.contains(body.replace("\n", "")), "PEM body in stack trace")
    }

    @Test
    fun unreadableKeyFailsWithAuthFailedWithoutLeakingIt(): Unit = blocking {
        val secretBody = "c2VjcmV0LW5vdC1hLXJlYWwta2V5LW1hdGVyaWFs"
        val pem = "-----BEGIN PRIVATE KEY-----\n$secretBody\n-----END PRIVATE KEY-----\n"
        val e = assertFailsWith<SshException.AuthFailed> {
            transport.connect(localTarget(), SshAuth.PrivateKey(pem, "pass-phrase-xyz".toCharArray()), RecordingVerifier())
        }
        val trace = e.stackTraceToString()
        assertFalse(trace.contains(secretBody), "PEM body in stack trace")
        assertFalse(trace.contains("pass-phrase-xyz"), "passphrase in stack trace")
    }

    @Test
    fun remoteTextIsSanitised() {
        val nasty = "bad\u0000\u001b[31m‮reversed\r\nline" + "x".repeat(500)
        val clean = sanitizeRemoteText(nasty)
        assertTrue(clean.length <= 200, "length ${clean.length}")
        assertTrue(clean.none { it.isISOControl() || it == '‮' })
        assertEquals("", sanitizeRemoteText(null))
    }

    // ---- connect cancellation, algorithms, keep-alive ------------------------------------------

    @Test
    fun cancellingConnectReturnsPromptlyAndClosesTheSocket(): Unit = blocking {
        BlackholeServer().use { hole ->
            val job = launch(Dispatchers.Default) {
                transport.connect(
                    SshTarget("127.0.0.1", hole.port, TEST_USER), password(), RecordingVerifier(),
                    options = SshConnectOptions(connectTimeoutMillis = 120_000),
                )
            }
            assertTrue(hole.awaitAccepted(10_000), "server never saw the connection")
            delay(300) // let sshj reach its blocking identification read
            val started = System.nanoTime()
            withTimeout(5_000) { job.cancelAndJoin() }
            val elapsedMillis = (System.nanoTime() - started) / 1_000_000
            assertTrue(elapsedMillis < 3_000, "cancel took $elapsedMillis ms")
            assertTrue(job.isCancelled)
            assertTrue(hole.awaitClientClosed(5_000), "client socket was not closed after cancellation")
        }
    }

    @Test
    fun modernProfileRefusesLegacyOnlyServerAndLegacyProfileConnects(): Unit = blocking {
        TestSshd(rsa.public as RSAPublicKey, legacyCryptoOnly = true).use { legacyServer ->
            val target = SshTarget("127.0.0.1", legacyServer.port, TEST_USER)

            // No automatic fallback: the default profile simply fails.
            assertFailsWith<SshException.Protocol> { transport.connect(target, password(), RecordingVerifier()) }
            assertFailsWith<SshException.Protocol> {
                transport.connect(
                    target, password(), RecordingVerifier(),
                    options = SshConnectOptions(algorithms = AlgorithmProfile.Modern),
                )
            }

            val session = transport.connect(
                target, password(), RecordingVerifier(),
                options = SshConnectOptions(algorithms = AlgorithmProfile.Legacy),
            )
            try {
                assertTrue(session.usesLegacyCrypto)
                assertEquals("diffie-hellman-group14-sha1", session.negotiated.kex)
                assertEquals("aes128-cbc", session.negotiated.cipherC2s)
                assertEquals("aes128-cbc", session.negotiated.cipherS2c)
                assertEquals("hmac-sha1", session.negotiated.macC2s)
                assertEquals("hmac-sha1", session.negotiated.macS2c)
                assertEquals("hello\n", String(session.exec("echo hello").stdout))
            } finally {
                session.close()
            }
        }
    }

    @Test
    fun legacyProfileStillPrefersModernAlgorithmsWhenAvailable(): Unit = blocking {
        val session = transport.connect(
            localTarget(), password(), RecordingVerifier(),
            options = SshConnectOptions(algorithms = AlgorithmProfile.Legacy),
        )
        try {
            assertFalse(session.usesLegacyCrypto, "negotiated ${session.negotiated}")
        } finally {
            session.close()
        }
    }

    @Test
    fun keepAliveDetectsDeadPeer(): Unit = blocking {
        val token = ByteArray(32) { 5 }
        TokenProxy(token, sshd.port).use { proxy ->
            val session = transport.connect(
                SshTarget("router.test.invalid", 2222, TEST_USER), password(), RecordingVerifier(),
                via = LoopbackPreamble(proxy.port, token),
                options = SshConnectOptions(keepAliveSeconds = 1, keepAliveMaxMissed = 2),
            )
            try {
                val shell = session.openShell(PtyRequest())
                val seen = CompletableDeferred<Unit>()
                val outcome = CompletableDeferred<Throwable?>()
                val collector = launch(Dispatchers.IO) {
                    try {
                        shell.output.collect { chunk -> if (String(chunk).contains("got:ping")) seen.complete(Unit) }
                        outcome.complete(null)
                    } catch (e: Throwable) {
                        outcome.complete(e)
                    }
                }
                shell.write("ping\n".toByteArray())
                withTimeout(10_000) { seen.await() }

                proxy.stalled = true // the path dies: nothing is forwarded in either direction any more
                val result = withTimeout(10_000) { outcome.await() }
                // Either the stream ended or it failed with an SshException; it must not hang or be cancelled.
                if (result != null) assertIs<SshException>(result)
                collector.cancel()
            } finally {
                session.close()
            }
        }
    }

    @Test
    fun noKeepAliveWhenDisabled(): Unit = blocking {
        // keepAliveSeconds = 0 must still connect and work (keep-alive thread simply not started).
        val session = transport.connect(
            localTarget(), password(), RecordingVerifier(),
            options = SshConnectOptions(keepAliveSeconds = 0),
        )
        try {
            assertEquals("hello\n", String(session.exec("echo hello").stdout))
        } finally {
            session.close()
        }
    }
}
