// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.security.MessageDigest
import java.security.SecureRandom
import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultException

/**
 * [VaultCodecHooks] backed by an [OpenVault] (which holds the data key). Remote files are opened with the data
 * key, so no password is needed during sync.
 *
 * The hooks keep their own copy of the vault; the caller keeps ownership of the instance it passed in. After a
 * local slot change or key rotation (changePassword, addDeviceSlot, removeSlot) hand the result to
 * [replaceVault]: the next upload then carries the new header. After a rotation the previous key is kept (at most
 * [MAX_RETIRED] generations, in memory only) so the remote and base files of the old epoch can still be read and
 * merged once; it is dropped as soon as a file of the current epoch has been read.
 *
 * Header selection on upload: when the file being replaced belongs to the same vault and key epoch and its header
 * revision is at least as new as the local one, its header (slots) is kept, so a slot change made on another
 * device is not undone. Otherwise the local header is written.
 *
 * Call [close] when finished; it zeroes every key copy held here.
 */
class OpenVaultCodecHooks(vault: OpenVault) : VaultCodecHooks, AutoCloseable {
    private val lock = Any()
    private var current: OpenVault = vault.withContent(vault.content)
    private val retired = ArrayList<OpenVault>()
    private val random = SecureRandom()

    override val keyEpoch: Long get() = synchronized(lock) { current.keyEpoch }

    override val headerRevision: Long get() = synchronized(lock) { current.headerRevision }

    override fun decrypt(bytes: ByteArray): DecryptedVault = synchronized(lock) {
        val info = VaultCodec.inspect(bytes)
        val key = if (info.keyEpoch == current.keyEpoch) {
            current
        } else {
            retired.firstOrNull { it.keyEpoch == info.keyEpoch }
                ?: throw VaultException.KeyEpochMismatch(found = info.keyEpoch, expected = current.keyEpoch)
        }
        val opened = VaultCodec.openWithDataKey(bytes, key)
        try {
            if (key === current) dropRetired()
            DecryptedVault(opened.content, opened.keyEpoch, opened.headerRevision)
        } finally {
            opened.close()
        }
    }

    override fun encrypt(content: VaultContent, replacing: ByteArray?): EncryptedVault = synchronized(lock) {
        if (replacing != null) adoptRemoteHeader(replacing)
        val toSeal = current.withContent(content)
        try {
            EncryptedVault(VaultCodec.seal(toSeal), toSeal.keyEpoch, toSeal.headerRevision)
        } finally {
            toSeal.close()
        }
    }

    override fun fingerprint(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    override fun randomToken(): String {
        val b = ByteArray(12)
        random.nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    /** A copy of the vault as the hooks currently hold it (with its newest header); the caller closes it. */
    fun currentVault(): OpenVault = synchronized(lock) { current.withContent(current.content) }

    /**
     * Adopts [newVault] (the result of a local slot change or rotation) as the vault to upload. When its key
     * epoch is higher the previous key is retired, not discarded. The caller keeps ownership of [newVault].
     */
    fun replaceVault(newVault: OpenVault) {
        synchronized(lock) {
            require(newVault.vaultId == current.vaultId) { "Replacement belongs to a different vault" }
            require(newVault.keyEpoch >= current.keyEpoch) { "Replacement has an older key epoch" }
            val copy = newVault.withContent(newVault.content)
            val old = current
            current = copy
            if (copy.keyEpoch > old.keyEpoch) {
                retired.add(old)
                while (retired.size > MAX_RETIRED) retired.removeAt(0).close()
            } else {
                old.close()
            }
        }
    }

    override fun close() {
        synchronized(lock) {
            current.close()
            dropRetired()
        }
    }

    private fun dropRetired() {
        retired.forEach { it.close() }
        retired.clear()
    }

    private fun adoptRemoteHeader(replacing: ByteArray) {
        val info = VaultCodec.inspect(replacing)
        if (info.vaultId != current.vaultId || info.keyEpoch != current.keyEpoch) return
        if (info.headerRevision < current.headerRevision) return
        val adopted = VaultCodec.openWithDataKey(replacing, current)
        val old = current
        current = adopted.withContent(old.content)
        adopted.close()
        old.close()
    }

    companion object {
        const val MAX_RETIRED = 2
    }
}

/** Wall-clock milliseconds, for [SyncEngine]'s `clock` parameter. */
fun systemClockMillis(): Long = System.currentTimeMillis()
