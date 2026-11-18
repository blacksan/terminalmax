// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.VaultContent

/** A remote file after authentication: its content and the (authenticated) key epoch and header revision. */
class DecryptedVault(val content: VaultContent, val keyEpoch: Long, val headerRevision: Long)

/** A sealed file together with the key epoch and header revision it was written with. */
class EncryptedVault(val bytes: ByteArray, val keyEpoch: Long, val headerRevision: Long)

/**
 * The encryption side of sync, kept behind an interface so the engine is pure Kotlin. [decrypt] and [encrypt] throw
 * [org.terminalmax.core.vault.VaultException] on failure.
 */
interface VaultCodecHooks {
    /** Key epoch of the header this device would write (the key it holds). */
    val keyEpoch: Long

    /** Header revision this device would write when it has no newer remote header to adopt. */
    val headerRevision: Long

    /**
     * Decrypts and authenticates a vault file. Throws `VaultException.KeyEpochMismatch` when the file belongs to a
     * key epoch whose key this device does not hold (newer: the device must re-open the vault; older: replay).
     */
    fun decrypt(bytes: ByteArray): DecryptedVault

    /**
     * Encrypts [content] into a vault file. [replacing] is the remote file being replaced (null for a first
     * upload). The header written is the one with the highest header revision known: the remote one when it is at
     * least as new as the local one, otherwise the local one (after a local slot change or key rotation).
     */
    fun encrypt(content: VaultContent, replacing: ByteArray?): EncryptedVault

    /** SHA-256 of [bytes] as lower-case hex (used to detect two different files with the same revision). */
    fun fingerprint(bytes: ByteArray): String

    /** An unpredictable token for lock leases. */
    fun randomToken(): String
}
