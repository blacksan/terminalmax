// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/**
 * Errors raised by the vault layer. Messages never contain key material, passwords or record data.
 */
sealed class VaultException(message: String, cause: Throwable? = null) : Exception(message, cause) {

    /** Authentication failed: wrong password / key, or the file was modified. Deliberately not distinguished. */
    class BadPasswordOrCorrupt(cause: Throwable? = null) :
        VaultException("Wrong password, or the vault data is corrupt", cause)

    /** The input is not a vault file at all, or its framing is malformed (truncated, oversized, bad magic). */
    class InvalidFormat(detail: String) : VaultException("Not a valid vault file: $detail")

    /** The file or its content was written by a newer, incompatible version of the app. */
    class UnsupportedVersion(val found: Int, val supported: Int) :
        VaultException("Unsupported vault version $found (this app supports up to $supported)")

    /** Two vaults with different vault ids were asked to merge. */
    class DifferentVault : VaultException("The vaults have different identities and cannot be merged")

    /** Key-derivation parameters in the file are outside the accepted bounds (or cannot be afforded). */
    class KdfParamsOutOfRange(detail: String) : VaultException("Key derivation parameters rejected: $detail")

    /** The requested key slot does not exist. */
    class NoSuchSlot : VaultException("No such key slot")
}
