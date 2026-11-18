// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.security.MessageDigest
import java.security.SecureRandom
import org.terminalmax.core.vault.EpochLinkStatus
import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent
import org.terminalmax.core.vault.VaultException

/**
 * [VaultCodecHooks] backed by an [OpenVault] (which holds the data key). Remote files are opened with the data
 * key, so no password is needed during sync. Owned by `VaultSession`; not part of the public API.
 *
 * The hooks keep their own copy of the vault. They always hold the newest **authenticated** header they have read:
 * when a file at the current key epoch has a header at least as new as the held one, it replaces the held one (within
 * one epoch the slot set only grows, and the file is authenticated by the same key), so a device never writes back
 * a stale header.
 *
 * Key changes happen in exactly three places, each of which zeroes the superseded key right away: [reopen] (the
 * vault was re-keyed elsewhere; opened with the password), [commitStaged] (a password change this device published)
 * and [close]. Because a password change is committed only after the upload is confirmed, there is never an
 * unpublished newer key to remember, and no old keys are retained.
 */
internal class OpenVaultCodecHooks(vault: OpenVault) : VaultCodecHooks, AutoCloseable {
    private val lock = Any()
    private var current: OpenVault = vault.withContent(vault.content)
    private val random = SecureRandom()

    override val keyEpoch: Long get() = synchronized(lock) { current.keyEpoch }

    override val headerRevision: Long get() = synchronized(lock) { current.headerRevision }

    override fun decrypt(bytes: ByteArray): DecryptedVault = synchronized(lock) {
        val opened = VaultCodec.openWithDataKey(bytes, current)
        try {
            if (opened.headerRevision >= current.headerRevision) {
                val old = current
                current = opened.withContent(old.content)
                old.close()
            }
            DecryptedVault(opened.content, opened.keyEpoch, opened.headerRevision)
        } finally {
            opened.close()
        }
    }

    override fun encrypt(content: VaultContent): EncryptedVault = synchronized(lock) {
        val toSeal = current.withContent(content)
        try {
            EncryptedVault(VaultCodec.seal(toSeal), toSeal.keyEpoch, toSeal.headerRevision)
        } finally {
            toSeal.close()
        }
    }

    override fun sealLocal(content: VaultContent): ByteArray = synchronized(lock) {
        val toSeal = current.withContent(content)
        try {
            VaultCodec.seal(toSeal)
        } finally {
            toSeal.close()
        }
    }

    override fun epochChain(bytes: ByteArray): EpochChain = synchronized(lock) {
        when (VaultCodec.verifyEpochLink(bytes, current)) {
            EpochLinkStatus.Verified -> EpochChain.Verified
            EpochLinkStatus.Unverified -> EpochChain.Unverified
            EpochLinkStatus.NotApplicable -> EpochChain.NotApplicable
        }
    }

    override fun reopen(bytes: ByteArray, password: CharArray): ReopenResult = synchronized(lock) {
        val opened = VaultCodec.open(bytes, password)
        try {
            if (opened.vaultId != current.vaultId) throw VaultException.DifferentVault()
            if (opened.keyEpoch <= current.keyEpoch) throw VaultException.BadPasswordOrCorrupt()
            val chain = epochChain(bytes)
            val old = current
            current = opened.withContent(old.content)
            old.close()
            ReopenResult(chain)
        } finally {
            opened.close()
        }
    }

    // ---- staged password change

    private class Staged(
        val vault: OpenVault,
        override val baseKeyEpoch: Long,
        override val baseHeaderRevision: Long,
    ) : StagedHeaderChange {
        override val keyEpoch: Long get() = vault.keyEpoch
        override val headerRevision: Long get() = vault.headerRevision
        var committed = false

        override fun discard() {
            if (!committed) vault.close()
        }
    }

    /**
     * Prepares a header change: [build] receives a copy of the held vault and returns the changed one (for example
     * `VaultCodec.changePassword`). Nothing is held or published until [commitStaged]; a failed or abandoned change
     * is released with [StagedHeaderChange.discard].
     */
    fun stage(build: (OpenVault) -> OpenVault): StagedHeaderChange = synchronized(lock) {
        val copy = current.withContent(current.content)
        try {
            Staged(build(copy), current.keyEpoch, current.headerRevision)
        } finally {
            copy.close()
        }
    }

    private fun asStaged(change: StagedHeaderChange): Staged =
        change as? Staged ?: throw IllegalArgumentException("Foreign staged change")

    override fun encryptStaged(content: VaultContent, staged: StagedHeaderChange): EncryptedVault = synchronized(lock) {
        val toSeal = asStaged(staged).vault.withContent(content)
        try {
            EncryptedVault(VaultCodec.seal(toSeal), toSeal.keyEpoch, toSeal.headerRevision)
        } finally {
            toSeal.close()
        }
    }

    override fun sealLocalStaged(content: VaultContent, staged: StagedHeaderChange): ByteArray = synchronized(lock) {
        val toSeal = asStaged(staged).vault.withContent(content)
        try {
            VaultCodec.seal(toSeal)
        } finally {
            toSeal.close()
        }
    }

    override fun commitStaged(staged: StagedHeaderChange) {
        synchronized(lock) {
            val change = asStaged(staged)
            check(!change.committed) { "Already committed" }
            require(change.vault.vaultId == current.vaultId) { "Replacement belongs to a different vault" }
            val old = current
            current = change.vault
            change.committed = true
            old.close()
        }
    }

    /** A per-device convenience-unlock secret for the held key (see [OpenVault.exportLocalUnlockSecret]). */
    fun exportLocalUnlockSecret(): ByteArray = synchronized(lock) { current.exportLocalUnlockSecret() }

    override fun fingerprint(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    override fun randomToken(): String {
        val b = ByteArray(12)
        random.nextBytes(b)
        return b.joinToString("") { "%02x".format(it) }
    }

    override fun close() {
        synchronized(lock) { current.close() }
    }
}

/** Wall-clock milliseconds, for `VaultSession`'s and [SyncEngine]'s `clock` parameters. */
fun systemClockMillis(): Long = System.currentTimeMillis()
