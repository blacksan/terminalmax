// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/**
 * Errors raised by the vault layer. Messages never contain key material, passwords or record data.
 */
sealed class VaultException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /**
     * Authentication failed before any key slot could be unwrapped, or no data key matched: wrong password / key,
     * or the file was modified. Deliberately not distinguished.
     */
    class BadPasswordOrCorrupt(cause: Throwable? = null) :
        VaultException("Wrong password, or the vault data is corrupt", cause)

    /**
     * A key slot unwrapped with the supplied secret but the content failed authentication: the password was right
     * and the file was modified or damaged. Tell the user to distrust the file, not to reset the password.
     */
    class IntegrityFailure(cause: Throwable? = null) :
        VaultException("The vault file failed its integrity check", cause)

    /** The input is not a vault file at all, or its framing is malformed (truncated, oversized, bad magic). */
    class InvalidFormat(detail: String) : VaultException("Not a valid vault file: $detail")

    /** The file or its content was written by a newer, incompatible version of the app. */
    class UnsupportedVersion(val found: Int, val supported: Int) :
        VaultException("Unsupported vault version $found (this app supports up to $supported)")

    /** Two vaults with different vault ids were asked to merge. */
    class DifferentVault : VaultException("The vaults have different identities and cannot be merged")

    /** Key-derivation parameters in the file are outside the accepted bounds. */
    class KdfParamsOutOfRange(detail: String) : VaultException("Key derivation parameters rejected: $detail")

    /** The key-derivation work a file asks for exceeds the platform ceiling or the per-file budget. */
    class KdfCostTooHigh(detail: String) : VaultException("Key derivation cost rejected: $detail")

    /** Authentic (or locally produced) content that violates the content rules (bounds, duplicate ids, ...). */
    class InvalidContent(detail: String) : VaultException("Invalid vault content: $detail")

    /**
     * The file belongs to another key epoch than the data key that was offered. [found] > [expected]: the vault
     * key was rotated elsewhere and this device must re-open the vault through its own key slot. [found] <
     * [expected]: an older file (replay) that this key cannot read.
     */
    class KeyEpochMismatch(val found: Long, val expected: Long) :
        VaultException("Vault key epoch $found does not match the key epoch $expected in use")

    /**
     * A file of the **same vault, key epoch and key** as the one in use whose header differs from the one this device
     * holds (another slot, other KDF parameters, another epoch link). Within one key epoch the header never changes
     * (any change of the password slot is a rotation to the next epoch), so such a file was written by someone who
     * holds the data key but is not following the format: a compromised device or a malicious co-user. It is refused
     * outright: not merged, not adopted, nothing re-sealed.
     */
    class HeaderMismatchSameEpoch : VaultException("A file of the same key epoch carries a different header")

    /**
     * A file of the **same vault and key epoch** but under a different data key (the key commitment differs): two
     * rotations to the same epoch raced, or someone minted a competing epoch. A password may open it (see
     * `VaultCodecHooks.reopen`); the data key in use cannot.
     */
    class KeyMismatchSameEpoch : VaultException("A file of the same key epoch is under a different data key")
}
