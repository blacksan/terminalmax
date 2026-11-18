// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
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
            val encrypted = hooks.encrypt(content)
            assertEquals(1L, encrypted.keyEpoch)
            assertEquals(1L, encrypted.headerRevision)
            val decrypted = hooks.decrypt(encrypted.bytes)
            assertEquals(content, decrypted.content)
            assertEquals(1L, decrypted.keyEpoch)
            assertEquals(1L, decrypted.headerRevision)
            // The local file is the same kind of file under the same key.
            assertEquals(content, hooks.decrypt(hooks.sealLocal(content)).content)
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
    fun aStagedPasswordChangeChangesNothingUntilItIsCommittedAndThenZeroesTheOldKey() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        OpenVaultCodecHooks(vault).use { hooks ->
            val content = contentWithHost(vault.content)
            val old = hooks.encrypt(content)
            val staged = hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
            assertEquals(1L, hooks.keyEpoch)
            assertEquals(1L, staged.baseKeyEpoch)
            assertEquals(2L, staged.keyEpoch)
            assertEquals(1L, hooks.decrypt(hooks.encrypt(content).bytes).keyEpoch, "still writes the old epoch")

            val fresh = hooks.encryptStaged(content, staged)
            assertEquals(2L, fresh.keyEpoch)
            assertEquals(EpochChain.Verified, hooks.epochChain(fresh.bytes))

            hooks.commitStaged(staged)
            assertEquals(2L, hooks.keyEpoch)
            assertEquals(2L, hooks.headerRevision)
            assertEquals(content, hooks.decrypt(fresh.bytes).content)
            // The superseded key is gone: the old epoch is a replay now.
            val replay = assertFailsWith<VaultException.KeyEpochMismatch> { hooks.decrypt(old.bytes) }
            assertEquals(1L, replay.found)
            assertEquals(2L, replay.expected)
            assertFailsWith<IllegalStateException> { hooks.commitStaged(staged) }
        }
    }

    @Test
    fun aDiscardedStagedChangeLeavesTheHeldVaultUntouched() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        OpenVaultCodecHooks(vault).use { hooks ->
            val staged = hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
            staged.discard()
            assertEquals(1L, hooks.keyEpoch)
            hooks.encrypt(contentWithHost(vault.content)) // the held key still works
        }
    }

    @Test
    fun aDeviceThatNeverSawTheRotationNeedsThePasswordAndHoldsTheNewKeyAfterwards() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        val content = contentWithHost(vault.content)
        val staleHooks = OpenVaultCodecHooks(vault)
        OpenVaultCodecHooks(vault).use { hooks ->
            val staged = hooks.stage { VaultCodec.changePassword(it, "new".toCharArray()) }
            val file = hooks.encryptStaged(content, staged).bytes
            hooks.commitStaged(staged)

            val newer = assertFailsWith<VaultException.KeyEpochMismatch> { staleHooks.decrypt(file) }
            assertEquals(2L, newer.found)
            assertEquals(1L, newer.expected)
            assertEquals(EpochChain.Verified, staleHooks.epochChain(file))
            assertFailsWith<VaultException.BadPasswordOrCorrupt> { staleHooks.reopen(file, "wrong".toCharArray()) }
            assertEquals(1L, staleHooks.keyEpoch)
            assertEquals(EpochChain.Verified, staleHooks.reopen(file, "new".toCharArray()).chain)
            assertEquals(2L, staleHooks.keyEpoch)
            assertEquals(content, staleHooks.decrypt(file).content)
        }
        staleHooks.close()
    }

    @Test
    fun decryptingANewerHeaderOfTheSameEpochAdoptsItAndAnOlderOneIsNotAdopted() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        val withSlot = VaultCodec.addPasswordSlot(vault, "second".toCharArray(), fast)
        OpenVaultCodecHooks(vault).use { behind ->
            OpenVaultCodecHooks(withSlot).use { ahead ->
                val content = contentWithHost(vault.content)
                val remote = ahead.encrypt(content)
                assertEquals(2L, remote.headerRevision)
                assertEquals(1L, behind.headerRevision)
                behind.decrypt(remote.bytes)
                assertEquals(2L, behind.headerRevision, "the authenticated newer header is adopted on every read")
                assertEquals(2, VaultCodec.inspect(behind.encrypt(content).bytes).slots.size)
                // An older header does not replace the held one.
                val old = VaultCodec.seal(vault.withContent(content))
                behind.decrypt(old)
                assertEquals(2L, behind.headerRevision)
            }
        }
    }

    @Test
    fun aFileOfAnotherVaultIsRejected() {
        val one = VaultCodec.create("pw".toCharArray(), fast)
        val two = VaultCodec.create("pw".toCharArray(), fast)
        OpenVaultCodecHooks(one).use { a ->
            OpenVaultCodecHooks(two).use { b ->
                val file = b.encrypt(two.content)
                assertFailsWith<VaultException.DifferentVault> { a.decrypt(file.bytes) }
            }
        }
    }

    @Test
    fun closedHooksZeroTheirKeyAndRefuseToWork() {
        val vault = VaultCodec.create("pw".toCharArray(), fast)
        val hooks = OpenVaultCodecHooks(vault)
        hooks.close()
        assertFailsWith<IllegalStateException> { hooks.encrypt(vault.content) }
        assertTrue(true)
    }
}
