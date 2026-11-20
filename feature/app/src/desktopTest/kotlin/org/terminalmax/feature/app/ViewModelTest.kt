// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

import java.io.File
import java.nio.file.Files
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.terminalmax.core.ssh.HostKeyDecision
import org.terminalmax.core.ssh.SshAuth
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.KnownHostPayload

private const val KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private const val WG = "[Interface]\nPrivateKey = $KEY\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = $KEY\nEndpoint = 203.0.113.5:13231\nAllowedIPs = 10.0.0.0/24\n"

class ViewModelTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val dirs = ArrayList<File>()
    private val tinyKdf = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)

    @AfterTest
    fun tearDown() {
        scope.cancel()
        dirs.forEach { it.deleteRecursively() }
    }

    private fun newDir(): File = Files.createTempDirectory("tmx-vm-test").toFile().also { dirs += it }

    private fun vault(dir: File = newDir()) = VaultViewModel(scope, dir, tinyKdf)

    private suspend fun <T> StateFlow<T>.await(block: (T) -> Boolean): T = withTimeout(20_000) { first(block) }

    private fun unlockedVault(): VaultViewModel = runBlocking {
        val vm = vault()
        vm.create("correct horse battery", "correct horse battery")!!.join()
        assertEquals(VaultPhase.Unlocked, vm.state.value.phase)
        vm
    }

    @Test
    fun createLockAndUnlock() = runBlocking<Unit> {
        val dir = newDir()
        val vm = VaultViewModel(scope, dir, tinyKdf)
        assertEquals(VaultPhase.NoVault, vm.state.value.phase)
        vm.create("correct horse battery", "correct horse battery")!!.join()
        assertEquals(VaultPhase.Unlocked, vm.state.value.phase)
        assertNotNull(vm.session.value)
        vm.lock()
        assertEquals(VaultPhase.Locked, vm.state.value.phase)
        assertNull(vm.session.value)

        vm.unlock("wrong password")!!.join()
        assertEquals(VaultPhase.Locked, vm.state.value.phase)
        assertNotNull(vm.state.value.error)

        vm.unlock("correct horse battery")!!.join()
        assertEquals(VaultPhase.Unlocked, vm.state.value.phase)
        vm.lock()

        // A second view model on the same directory starts at the unlock screen.
        assertEquals(VaultPhase.Locked, VaultViewModel(scope, dir, tinyKdf).state.value.phase)
    }

    @Test
    fun createRejectsShortAndMismatchedPasswords() {
        val vm = vault()
        assertNull(vm.create("short", "short"))
        assertTrue(vm.state.value.error!!.contains("at least"))
        assertNull(vm.create("long enough password", "different password"))
        assertTrue(vm.state.value.error!!.contains("not the same"))
        assertEquals(VaultPhase.NoVault, vm.state.value.phase)
        assertFalse(vm.state.value.busy)
    }

    @Test
    fun lockRunsTheLockHook() = runBlocking<Unit> {
        var locked = 0
        val vm = VaultViewModel(scope, newDir(), tinyKdf, onLocked = { locked++ })
        vm.create("correct horse battery", "correct horse battery")!!.join()
        vm.lock()
        assertEquals(1, locked)
        vm.lock() // already locked: nothing happens
        assertEquals(1, locked)
    }

    @Test
    fun hostCrudWithPasswordLogin() = runBlocking<Unit> {
        val vault = unlockedVault()
        val hosts = HostsViewModel(scope, vault)
        val draft = HostDraft(label = "Core router", address = "192.168.88.1", username = "admin", password = "secret", consoleOptions = "ct80w")
        assertTrue(hosts.saveHost(draft).ok)
        val saved = hosts.allHosts.await { it.size == 1 }.single()
        assertEquals("Core router", saved.label)
        assertEquals("admin+ct80w", saved.sshUsername)
        assertEquals("admin@192.168.88.1:22", saved.subtitle)

        val content = vault.session.value!!.content.value
        val auth = content.authFor(saved)
        assertIs<SshAuth.Password>(auth)
        assertEquals("secret", String(auth.password))

        // Editing without typing a password keeps the stored one.
        val edit = hosts.loadDraft(saved.id)
        assertEquals("", edit.password)
        assertTrue(edit.hasStoredPassword)
        assertTrue(hosts.saveHost(edit.copy(label = "Renamed")).ok)
        val renamed = hosts.allHosts.await { it.singleOrNull()?.label == "Renamed" }.single()
        assertEquals(saved.id, renamed.id)
        assertEquals(saved.identityId, renamed.identityId)
        assertEquals("secret", String((vault.session.value!!.content.value.authFor(renamed) as SshAuth.Password).password))

        // Search.
        hosts.setQuery("zzz")
        hosts.hosts.await { it.isEmpty() }
        hosts.setQuery("rename")
        assertEquals(1, hosts.hosts.await { it.size == 1 }.size)

        assertNull(hosts.deleteHost(saved.id))
        hosts.allHosts.await { it.isEmpty() }
        // The identity went with the host.
        assertEquals(0, vault.session.value!!.content.value.records.count { !it.deleted && it.type != org.terminalmax.core.vault.RecordType.KnownHost })
    }

    @Test
    fun hostWithPrivateKeyStoresIdentityAndKeyRecords() = runBlocking<Unit> {
        val vault = unlockedVault()
        val hosts = HostsViewModel(scope, vault)
        val pem = "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"
        val draft = HostDraft(label = "Server", address = "example.org", username = "root", auth = AuthKind.Key, privateKeyPem = pem, passphrase = "pp", legacy = true)
        assertTrue(hosts.saveHost(draft).ok)
        val host = hosts.allHosts.await { it.size == 1 }.single()
        assertTrue(host.legacy)
        val auth = vault.session.value!!.content.value.authFor(host)
        assertIs<SshAuth.PrivateKey>(auth)
        assertTrue(auth.pem.contains("OPENSSH PRIVATE KEY"))
        assertEquals("pp", String(auth.passphrase!!))
        val live = vault.session.value!!.content.value.records.filter { !it.deleted }
        assertEquals(setOf("Host", "Identity", "PrivateKey"), live.map { it.wireTypeName }.toSet())

        // Switching to a password removes the key record.
        val edit = hosts.loadDraft(host.id)
        assertEquals(AuthKind.Key, edit.auth)
        assertTrue(edit.hasStoredKey)
        assertEquals("", edit.privateKeyPem)
        assertTrue(hosts.saveHost(edit.copy(auth = AuthKind.Password, password = "pw")).ok)
        hosts.allHosts.await { it.size == 1 }
        val after = vault.session.value!!.content.value.records.filter { !it.deleted }.map { it.wireTypeName }.toSet()
        assertEquals(setOf("Host", "Identity"), after)
    }

    @Test
    fun invalidDraftIsRejectedWithoutWriting() = runBlocking<Unit> {
        val vault = unlockedVault()
        val hosts = HostsViewModel(scope, vault)
        val result = hosts.saveHost(HostDraft(label = "x", address = "router.example", username = "u", wireGuardProfileId = "p"))
        assertFalse(result.ok)
        assertTrue(HostField.Address in result.fieldErrors)
        assertEquals(0, vault.session.value!!.content.value.records.size)
    }

    @Test
    fun wireGuardImportValidatesAndHidesTheKey() = runBlocking<Unit> {
        val vault = unlockedVault()
        val hosts = HostsViewModel(scope, vault)
        val bad = hosts.importProfile("Home", "[Interface]\nAddress = 10.0.0.2/32\n")
        assertFalse(bad.ok)
        assertTrue(bad.messages.isNotEmpty())
        assertEquals(0, hosts.profiles.value.size)

        assertFalse(hosts.importProfile(" ", WG).ok)
        assertTrue(hosts.importProfile("Home", WG).ok)
        val p = hosts.profiles.await { it.size == 1 }.single()
        assertEquals("Home", p.label)
        assertEquals("10.0.0.2/32", p.address)
        assertEquals("203.0.113.5:13231", p.endpoint)
        assertFalse(p.toString().contains(KEY))

        // A host that uses the profile loses the link when the profile is deleted.
        assertTrue(hosts.saveHost(HostDraft(label = "Via tunnel", address = "10.0.0.1", username = "admin", wireGuardProfileId = p.id)).ok)
        hosts.allHosts.await { it.singleOrNull()?.wireGuardProfileId == p.id }
        assertNull(hosts.deleteProfile(p.id))
        hosts.profiles.await { it.isEmpty() }
        assertNull(hosts.allHosts.await { it.singleOrNull()?.wireGuardProfileId == null }.single().wireGuardProfileId)
    }

    @Test
    fun knownHostVerifierDecisions() {
        val key = byteArrayOf(1, 2, 3)
        val other = byteArrayOf(9, 9, 9)
        val enc = Base64.getEncoder()
        val verifier = knownHostVerifier(
            listOf(KnownHostPayload("10.0.0.1", 22, "ssh-ed25519", "SHA256:x", enc.encodeToString(key))),
        )
        assertEquals(HostKeyDecision.Trusted, verifier.check("10.0.0.1", 22, "ssh-ed25519", "SHA256:x", key))
        assertEquals(HostKeyDecision.Mismatch, verifier.check("10.0.0.1", 22, "ssh-ed25519", "SHA256:y", other))
        assertEquals(HostKeyDecision.Unknown, verifier.check("10.0.0.1", 22, "ssh-rsa", "SHA256:z", other))
        assertEquals(HostKeyDecision.Unknown, verifier.check("10.0.0.2", 22, "ssh-ed25519", "SHA256:x", key))
        assertEquals(HostKeyDecision.Unknown, verifier.check("10.0.0.1", 2222, "ssh-ed25519", "SHA256:x", key))
        assertEquals(listOf("ssh-ed25519"), verifier.knownKeyTypes("10.0.0.1", 22))
    }

    @Test
    fun trustingAndReplacingHostKeys() = runBlocking<Unit> {
        val vault = unlockedVault()
        val session = vault.session.value!!
        session.trustHostKey("10.0.0.1", 22, "ssh-ed25519", "SHA256:a", byteArrayOf(1), replace = false)
        assertEquals(1, session.content.value.knownHosts().size)
        session.trustHostKey("10.0.0.1", 22, "ssh-ed25519", "SHA256:b", byteArrayOf(2), replace = true)
        val known = session.content.value.knownHosts()
        assertEquals(1, known.size)
        assertEquals("SHA256:b", known.single().second.fingerprintSha256)
    }

    @Test
    fun syncConfigRoundTripsThroughTheVault() = runBlocking<Unit> {
        val vault = unlockedVault()
        val prefs = AppPrefs(null)
        val sync = SyncViewModel(scope, vault, prefs)
        assertNull(sync.saveConfig("https://dav.example.org/tmx/", "me", "pw"))
        val cfg = vault.session.value!!.content.value.syncConfig()
        assertEquals("https://dav.example.org/tmx/", cfg!!.url)
        assertEquals("me", cfg.username)
        assertEquals("pw", cfg.password)
        // A plain http address on a non-loopback host is refused by the WebDAV client.
        assertNotNull(sync.saveConfig("http://dav.example.org/", "me", "pw"))
        assertFalse(cfg.toString().contains("pw"))
    }

    @Test
    fun preferencesAreStoredOutsideTheVault() {
        val file = File(newDir(), "prefs.properties")
        val a = AppPrefs(file)
        assertEquals(ThemeMode.System, a.themeMode.value)
        a.setThemeMode(ThemeMode.Dark)
        a.setTerminalFontSp(99)
        a.setAutoSync(true)
        val b = AppPrefs(file)
        assertEquals(ThemeMode.Dark, b.themeMode.value)
        assertEquals(AppPrefs.MAX_FONT_SP, b.terminalFontSp.value)
        assertTrue(b.autoSync.value)
    }
}
