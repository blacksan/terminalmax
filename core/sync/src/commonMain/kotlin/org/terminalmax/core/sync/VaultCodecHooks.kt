// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.VaultContent

/** A remote file after authentication: its content and the (authenticated) key epoch. */
class DecryptedVault(val content: VaultContent, val keyEpoch: Long)

/** A sealed file together with the key epoch it was written with. */
class EncryptedVault(val bytes: ByteArray, val keyEpoch: Long)

/** How a file at a higher key epoch relates to the key this device holds (see `VaultCodec.verifyEpochLink`). */
enum class EpochChain { Verified, Unverified, NotApplicable }

/**
 * The result of opening a re-keyed remote file with the password.
 *
 * @property chain whether the re-key was linked to this device's key
 * @property sameEpoch the file was at the same key epoch as the key this device held (a competing key)
 * @property passwordUnchanged the password also opens this device's previous header: the "re-key" kept the password
 *   (an old password typed into a file minted by someone who knew it)
 */
class ReopenResult(val chain: EpochChain, val sameEpoch: Boolean = false, val passwordUnchanged: Boolean = false)

/**
 * A header change (a password change, which replaces the data key) that has been prepared but not yet published. It
 * is only ever made visible through one sync transaction: the engine uploads the new file and commits the change
 * locally only after the upload is confirmed, so a crash before that leaves the old epoch untouched.
 *
 * @property baseKeyEpoch key epoch of the header the change was derived from
 * @property keyEpoch key epoch the change will have
 */
interface StagedHeaderChange {
    val baseKeyEpoch: Long
    val keyEpoch: Long

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

    /**
     * Decrypts and authenticates a vault file with the key this device holds. **The header is immutable within a key
     * epoch**: a file of the same epoch and key whose header differs from the held one is refused with
     * `VaultException.HeaderMismatchSameEpoch` (nothing is adopted, merged or re-sealed). Other failures:
     * `KeyEpochMismatch` (another key epoch: newer means the vault was re-keyed and the password is needed, older is
     * a replay) and `KeyMismatchSameEpoch` (the same epoch under another key: a password may open it, see [reopen]).
     */
    fun decrypt(bytes: ByteArray): DecryptedVault

    /** Encrypts [content] into a vault file with the header this device holds. */
    fun encrypt(content: VaultContent): EncryptedVault

    /** Seals [content] as this device's local vault file (same header and key as [encrypt]). */
    fun sealLocal(content: VaultContent): ByteArray

    /** How the (unauthenticated) epoch of [bytes] relates to the key this device holds; nothing is decrypted. */
    fun epochChain(bytes: ByteArray): EpochChain

    /**
     * Opens a remote file at a higher key epoch (or at the same epoch under another key) with the master
     * [password] and holds its key from now on. The superseded key is zeroed. Throws
     * `VaultException.BadPasswordOrCorrupt` for a wrong password or a file that is not a different key, and
     * `KdfCostTooHigh` when the file asks for more key-derivation memory than this device accepts.
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
