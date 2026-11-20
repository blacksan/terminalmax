// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import org.terminalmax.core.terminal.KeyModifiers
import org.terminalmax.core.terminal.TerminalKey

private const val KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

private fun config(
    privateKey: String? = KEY,
    address: String? = "10.0.0.2/32",
    publicKey: String? = KEY,
    endpoint: String? = "203.0.113.5:13231",
    allowed: String? = "10.0.0.0/24",
): String = buildString {
    appendLine("[Interface]")
    if (privateKey != null) appendLine("PrivateKey = $privateKey")
    if (address != null) appendLine("Address = $address")
    appendLine("DNS = 10.0.0.1")
    appendLine()
    appendLine("[Peer]")
    if (publicKey != null) appendLine("PublicKey = $publicKey")
    if (endpoint != null) appendLine("Endpoint = $endpoint")
    if (allowed != null) appendLine("AllowedIPs = $allowed # comment")
    appendLine("PersistentKeepalive = 25")
}

class WgConfigTest {
    @Test
    fun validConfigIsAccepted() {
        val v = validateWgConfig(config())
        val info = assertIs<WgValidation.Valid>(v).info
        assertEquals("10.0.0.2/32", info.address)
        assertEquals("203.0.113.5:13231", info.endpoint)
        assertEquals("10.0.0.0/24", info.allowedIps)
    }

    @Test
    fun missingFieldsAreReported() {
        for (bad in listOf(config(privateKey = null), config(address = null), config(publicKey = null), config(endpoint = null), config(allowed = null))) {
            assertIs<WgValidation.Invalid>(validateWgConfig(bad))
        }
    }

    @Test
    fun malformedKeyAndEndpoint() {
        assertIs<WgValidation.Invalid>(validateWgConfig(config(privateKey = "not-a-key")))
        assertIs<WgValidation.Invalid>(validateWgConfig(config(endpoint = "host-without-port")))
        assertIs<WgValidation.Invalid>(validateWgConfig(config(endpoint = "host:99999")))
        assertIs<WgValidation.Valid>(validateWgConfig(config(endpoint = "[2001:db8::1]:51820")))
    }

    @Test
    fun errorsNeverContainKeyMaterial() {
        val secret = "SECRETSECRETSECRETSECRETSECRETSECRETSECRE="
        val result = validateWgConfig(config(privateKey = secret, endpoint = null))
        val errors = assertIs<WgValidation.Invalid>(result).errors
        assertTrue(errors.isNotEmpty())
        assertFalse(errors.any { it.contains("SECRETSECRET") })
    }

    @Test
    fun emptyAndGarbage() {
        assertIs<WgValidation.Invalid>(validateWgConfig(""))
        assertIs<WgValidation.Invalid>(validateWgConfig("hello world"))
        assertIs<WgValidation.Invalid>(validateWgConfig("[Interface]\n[Interface]\n[Peer]\n"))
    }
}

class HostDraftTest {
    private fun ok() = HostDraft(label = "Router", address = "192.168.88.1", username = "admin")

    @Test
    fun validDraftHasNoErrors() {
        assertTrue(validateHostDraft(ok()).isEmpty())
    }

    @Test
    fun tunnelNeedsIpLiteral() {
        assertTrue(HostField.Address in validateHostDraft(ok().copy(address = "router.example.org", wireGuardProfileId = "p")))
        assertTrue(validateHostDraft(ok().copy(address = "10.0.0.1", wireGuardProfileId = "p")).isEmpty())
        assertTrue(validateHostDraft(ok().copy(address = "fd00::1", wireGuardProfileId = "p")).isEmpty())
        assertTrue(validateHostDraft(ok().copy(address = "router.example.org")).isEmpty())
    }

    @Test
    fun portUserAndLabel() {
        val errors = validateHostDraft(ok().copy(port = "0", username = " ", label = ""))
        assertTrue(HostField.Port in errors && HostField.Username in errors && HostField.Label in errors)
        assertTrue(HostField.Port in validateHostDraft(ok().copy(port = "70000")))
    }

    @Test
    fun keyAuthNeedsAPrivateKey() {
        assertTrue(HostField.Key in validateHostDraft(ok().copy(auth = AuthKind.Key)))
        assertTrue(HostField.Key in validateHostDraft(ok().copy(auth = AuthKind.Key, privateKeyPem = "hello")))
        assertTrue(validateHostDraft(ok().copy(auth = AuthKind.Key, privateKeyPem = "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----")).isEmpty())
        assertTrue(validateHostDraft(ok().copy(auth = AuthKind.Key, hasStoredKey = true)).isEmpty())
    }

    @Test
    fun consoleOptionsAreNormalised() {
        assertEquals("+ct80w", normalizeConsoleOptions("ct80w"))
        assertEquals("+ct80w", normalizeConsoleOptions(" +ct80w "))
        assertEquals("", normalizeConsoleOptions(" "))
        assertTrue(HostField.Options in validateHostDraft(ok().copy(consoleOptions = "+ct 80w;rm")))
        assertTrue(validateHostDraft(ok().copy(consoleOptions = "ct80w")).isEmpty())
    }

    @Test
    fun ipLiterals() {
        assertTrue(isIpLiteral("10.1.2.3"))
        assertTrue(isIpLiteral("::1"))
        assertTrue(isIpLiteral("2001:db8::ff00:42:8329"))
        assertFalse(isIpLiteral("256.1.1.1"))
        assertFalse(isIpLiteral("1.2.3"))
        assertFalse(isIpLiteral("example.org"))
        assertFalse(isIpLiteral("fe80::1%eth0"))
        assertFalse(isIpLiteral("[::1]"))
    }

    @Test
    fun passwordStrengthLevels() {
        assertEquals(PasswordStrength.TooShort, passwordStrength("abc"))
        assertEquals(PasswordStrength.Weak, passwordStrength("aaaaaaaaaaaa"))
        assertEquals(PasswordStrength.Strong, passwordStrength("correct horse battery staple"))
    }
}

class ExtraKeysTest {
    private val encode: (TerminalKey, KeyModifiers) -> ByteArray = { key, m ->
        // A stand-in for the engine: name and modifiers as text.
        "${key.name}:${if (m.ctrl) "C" else ""}${if (m.alt) "A" else ""}".encodeToByteArray()
    }

    @Test
    fun plainSymbolKeys() {
        assertContentEquals("|".encodeToByteArray(), encodeExtraKey(ExtraKey.Pipe, false, false, encode))
        assertContentEquals("-".encodeToByteArray(), encodeExtraKey(ExtraKey.Dash, false, false, encode))
        assertContentEquals("/".encodeToByteArray(), encodeExtraKey(ExtraKey.Slash, false, false, encode))
    }

    @Test
    fun modifierKeysOnlyToggle() {
        assertNull(encodeExtraKey(ExtraKey.Ctrl, false, false, encode))
        assertNull(encodeExtraKey(ExtraKey.Alt, true, false, encode))
        assertTrue(ExtraKey.Ctrl.isModifier && ExtraKey.Alt.isModifier && !ExtraKey.Esc.isModifier)
    }

    @Test
    fun namedKeysUseTheEncoderWithModifiers() {
        assertContentEquals("Escape:".encodeToByteArray(), encodeExtraKey(ExtraKey.Esc, false, false, encode))
        assertContentEquals("Left:C".encodeToByteArray(), encodeExtraKey(ExtraKey.Left, true, false, encode))
        assertContentEquals("PageDown:CA".encodeToByteArray(), encodeExtraKey(ExtraKey.PageDown, true, true, encode))
    }

    @Test
    fun everyKeyOfTheRowIsMapped() {
        for (k in ExtraKey.entries) {
            val bytes = encodeExtraKey(k, false, false, encode)
            if (k.isModifier) assertNull(bytes) else assertTrue(bytes!!.isNotEmpty())
        }
        assertEquals(15, ExtraKey.entries.size)
    }

    @Test
    fun ctrlAndAltOnTypedText() {
        assertContentEquals(byteArrayOf(3), encodeTypedText("c", ctrl = true, alt = false))
        assertContentEquals(byteArrayOf(3), encodeTypedText("C", ctrl = true, alt = false))
        assertContentEquals(byteArrayOf(0x1b, 'x'.code.toByte()), encodeTypedText("x", ctrl = false, alt = true))
        assertContentEquals(byteArrayOf(0x1b, 4), encodeTypedText("d", ctrl = true, alt = true))
        assertContentEquals(byteArrayOf(31), encodeTypedText("/", ctrl = true, alt = false))
        assertContentEquals("ls".encodeToByteArray(), encodeTypedText("ls", ctrl = false, alt = false))
        assertContentEquals(byteArrayOf(1, 'b'.code.toByte()), encodeTypedText("ab", ctrl = true, alt = false))
    }

    @Test
    fun newlineBecomesCarriageReturn() {
        assertContentEquals(byteArrayOf('a'.code.toByte(), 13), encodeTypedText("a\n", ctrl = false, alt = false))
    }
}

class NavigatorTest {
    @Test
    fun pushPopAndRoots() {
        val nav = Navigator()
        assertEquals(Screen.Hosts, nav.current)
        assertFalse(nav.canGoBack)
        assertFalse(nav.pop())
        nav.push(Screen.HostEditor(null))
        assertTrue(nav.canGoBack)
        assertEquals(Screen.HostEditor(null), nav.current)
        assertTrue(nav.pop())
        assertEquals(Screen.Hosts, nav.current)
        nav.push(Screen.Terminal(3))
        nav.switchTo(Screen.Settings)
        assertEquals(listOf<Screen>(Screen.Settings), nav.stack.value)
        nav.push(Screen.About)
        nav.replaceTop(Screen.SyncSettings)
        assertEquals(listOf(Screen.Settings, Screen.SyncSettings), nav.stack.value)
    }

    @Test
    fun pushingTheCurrentScreenAgainDoesNothing() {
        val nav = Navigator()
        nav.push(Screen.About)
        nav.push(Screen.About)
        assertEquals(2, nav.stack.value.size)
    }
}
