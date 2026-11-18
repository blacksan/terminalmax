// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import org.terminalmax.core.vault.HostPayload
import org.terminalmax.core.vault.KdfParams
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultEditor
import org.terminalmax.core.vault.VaultException

class OpenVaultCodecHooksTest {
    private val fast = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)

    private fun contentWithHost(base: VaultContent): VaultContent {
        val editor = VaultEditor(base, "A")
        editor.upsertHost(HostPayload("h", "10.0.0.1", 22, "u"), id = "h1")
        return editor.content
    }

    @Test
    fun encryptAndDecryptRoundTripAndReportTheAuthenticatedEpochAndHeaderRevision() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        OpenVaultCodecHooks(vault).use { hooks ->
            val content = contentWithHost(vault.content)
            val encrypted = hooks.encrypt(content, null)
            assertEquals(1L, encrypted.keyEpoch)
            assertEquals(1L, encrypted.headerRevision)
            val decrypted = hooks.decrypt(encrypted.bytes)
            assertEquals(content, decrypted.content)
            assertEquals(1L, decrypted.keyEpoch)
            assertEquals(1L, decrypted.headerRevision)
        }
    }

    @Test
    fun fingerprintsAreSha256HexAndTokensDiffer() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        OpenVaultCodecHooks(vault).use { hooks ->
            val a = hooks.fingerprint(byteArrayOf(1, 2, 3))
            assertEquals(64, a.length)
            assertEquals(a, hooks.fingerprint(byteArrayOf(1, 2, 3)))
            assertNotEquals(a, hooks.fingerprint(byteArrayOf(1, 2, 4)))
            assertEquals(
                "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
                hooks.fingerprint(byteArrayOf(1, 2, 3)),
            )
            assertNotEquals(hooks.randomToken(), hooks.randomToken())
        }
    }

    @Test
    fun aKeyRotationKeepsTheOldKeyUntilACurrentFileHasBeenRead() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        val stale = OpenVaultCodecHooks(vault)
        OpenVaultCodecHooks(vault).use { hooks ->
            val content = contentWithHost(vault.content)
            val old = hooks.encrypt(content, null)

            hooks.replaceVault(VaultCodec.changePassword(vault, "new".toCharArray()))
            assertEquals(2L, hooks.keyEpoch)
            assertEquals(2L, hooks.headerRevision)

            // The file of the previous epoch can still be read once (to merge it), then the new file is written.
            assertEquals(content, hooks.decrypt(old.bytes).content)
            val fresh = hooks.encrypt(content, old.bytes)
            assertEquals(2L, fresh.keyEpoch)
            assertEquals(2L, fresh.headerRevision)

            // Reading a file of the current epoch drops the old key: replays of the old epoch are refused.
            assertEquals(content, hooks.decrypt(fresh.bytes).content)
            val replay = assertFailsWith<VaultException.KeyEpochMismatch> { hooks.decrypt(old.bytes) }
            assertEquals(1L, replay.found)
            assertEquals(2L, replay.expected)

            // A device that never saw the rotation cannot read the new file and learns that it must re-open.
            val newer = assertFailsWith<VaultException.KeyEpochMismatch> { stale.decrypt(fresh.bytes) }
            assertEquals(2L, newer.found)
            assertEquals(1L, newer.expected)
        }
        stale.close()
    }

    @Test
    fun anUploadKeepsTheNewerHeaderOfTheFileItReplaces() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        val pair = VaultCodec.generateDeviceKeyPair()
        val withSlot = VaultCodec.addDeviceSlot(vault, pair.publicKey)
        OpenVaultCodecHooks(vault).use { behind ->
            OpenVaultCodecHooks(withSlot).use { ahead ->
                val content = contentWithHost(vault.content)
                val remote = ahead.encrypt(content, null)
                assertEquals(2L, remote.headerRevision)
                // `behind` has header revision 1 but must not undo the slot that is already on the server.
                val next = behind.encrypt(content, remote.bytes)
                assertEquals(2L, next.headerRevision)
                assertEquals(2L, behind.headerRevision)
                assertEquals(2, VaultCodec.inspect(next.bytes).slots.size)
            }
        }
    }

    @Test
    fun aLocalHeaderNewerThanTheRemoteOneWins() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        val pair = VaultCodec.generateDeviceKeyPair()
        OpenVaultCodecHooks(vault).use { hooks ->
            val content = contentWithHost(vault.content)
            val remote = hooks.encrypt(content, null)
            hooks.replaceVault(VaultCodec.addDeviceSlot(vault, pair.publicKey))
            val next = hooks.encrypt(content, remote.bytes)
            assertEquals(2L, next.headerRevision)
            assertEquals(2, VaultCodec.inspect(next.bytes).slots.size)
        }
    }

    @Test
    fun aFileOfAnotherVaultIsRejected() {
        val one = VaultCodec.create("pw".toCharArray(), fast)
        val two = VaultCodec.create("pw".toCharArray(), fast)
        OpenVaultCodecHooks(one).use { a ->
            OpenVaultCodecHooks(two).use { b ->
                val file = b.encrypt(two.content, null)
                assertFailsWith<VaultException.DifferentVault> { a.decrypt(file.bytes) }
            }
        }
    }
}
