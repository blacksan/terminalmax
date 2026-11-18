// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.VaultContent

/** A remote file after authentication: its content and the (authenticated) key epoch and header revision. */
class DecryptedVault(val content: VaultContent, val keyEpoch: Long, val headerRevision: Long)

/** A sealed file together with the key epoch and header revision it was written with. */
class EncryptedVault(val bytes: ByteArray, val keyEpoch: Long, val headerRevision: Long)

/** How a file at a higher key epoch relates to the key this device holds (see `VaultCodec.verifyEpochLink`). */
enum class EpochChain { Verified, Unverified, NotApplicable }

/** The result of opening a re-keyed remote file with the password. [chain] says whether the re-key was linked to this device's key. */
class ReopenResult(val chain: EpochChain)

/**
 * A header change (a password change, which replaces the data key) that has been prepared but not yet published. It
 * is only ever made visible through one sync transaction: the engine uploads the new file and commits the change
 * locally only after the upload is confirmed, so a crash before that leaves the old epoch untouched.
 *
 * @property baseKeyEpoch key epoch of the header the change was derived from
 * @property baseHeaderRevision header revision of the header the change was derived from
 */
interface StagedHeaderChange {
    val baseKeyEpoch: Long
    val baseHeaderRevision: Long
    val keyEpoch: Long
    val headerRevision: Long

    /** Releases the prepared key material without committing it. */
    fun discard()
}

/**
 * The encryption side of sync, kept behind an interface so the engine is pure Kotlin. Methods throw
 * [org.terminalmax.core.vault.VaultException] on failure.
 */
interface VaultCodecHooks {
    /** Key epoch of the header this device would write (the key it holds). */
    val keyEpoch: Long

    /** Header revision of the header this device would write: the newest authenticated one it has read. */
    val headerRevision: Long

    /**
     * Decrypts and authenticates a vault file. A file at the current key epoch whose header is at least as new as the
     * held one **replaces the held header** (the slot set can only grow within one epoch, and the file is
     * authenticated by the same key). Throws `VaultException.KeyEpochMismatch` when the file belongs to another key
     * epoch (newer: the vault was re-keyed and the password is needed; older: a replay).
     */
    fun decrypt(bytes: ByteArray): DecryptedVault

    /** Encrypts [content] into a vault file with the header this device holds. */
    fun encrypt(content: VaultContent): EncryptedVault

    /** Seals [content] as this device's local vault file (same header and key as [encrypt]). */
    fun sealLocal(content: VaultContent): ByteArray

    /** How the (unauthenticated) epoch of [bytes] relates to the key this device holds; nothing is decrypted. */
    fun epochChain(bytes: ByteArray): EpochChain

    /**
     * Opens a remote file at a higher key epoch with the master [password] and holds its key from now on. The
     * superseded key is zeroed. Throws `VaultException.BadPasswordOrCorrupt` for a wrong password.
     */
    fun reopen(bytes: ByteArray, password: CharArray): ReopenResult

    /** Like [encrypt], but with the header of [staged]. */
    fun encryptStaged(content: VaultContent, staged: StagedHeaderChange): EncryptedVault

    /** Like [sealLocal], but with the header of [staged]. */
    fun sealLocalStaged(content: VaultContent, staged: StagedHeaderChange): ByteArray

    /** Makes [staged] the header and key this device holds; the previous key is zeroed. */
    fun commitStaged(staged: StagedHeaderChange)

    /** SHA-256 of [bytes] as lower-case hex (used to detect two different files with the same revision). */
    fun fingerprint(bytes: ByteArray): String

    /** An unpredictable token for lock leases. */
    fun randomToken(): String
}
