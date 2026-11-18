// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.File

/**
 * Errors of [VaultSession] that are about the directory and its state, not about cryptography (those are
 * `org.terminalmax.core.vault.VaultException`). Messages never contain key material, passwords or record data.
 * Every subclass is an [IllegalStateException].
 */
sealed class VaultSessionException(message: String, cause: Throwable? = null) : IllegalStateException(message, cause) {

    /**
     * Another [VaultSession] (in this process or another one) holds the directory. A session holds an OS-level lock
     * on it for its whole lifetime and releases it on [VaultSession.close]; a second open fails immediately instead
     * of silently losing the other session's edits.
     */
    class DirectoryInUse(val directory: File) :
        VaultSessionException("The vault directory is in use by another session: $directory")

    /**
     * The state file in the directory cannot be read (it is damaged). Nothing was changed and nothing was deleted.
     * [VaultSession.salvage] reads the rolling previous copy (and the damaged file leniently) with the vault
     * password and reports what could be recovered; `FileLocalStateStore.reset` never deletes the vault content.
     */
    class StateUnreadable(cause: Throwable?) :
        VaultSessionException("The vault state file is unreadable; use VaultSession.salvage to recover from it", cause)

    /** The directory holds no vault. */
    class NoVault : VaultSessionException("This directory holds no vault")

    /** The directory holds more than one vault (not something a session creates). */
    class AmbiguousDirectory : VaultSessionException("This directory holds more than one vault")

    /** [VaultSession.create], [VaultSession.join] or [VaultSession.importBackup] found a vault in the directory already. */
    class DirectoryHoldsVault : VaultSessionException("This directory already holds a vault")

    /** [VaultSession.join]: the remote has no vault file to join. */
    class RemoteHasNoVault : VaultSessionException("The remote holds no vault file to join")

    /** The operation needs an explicit confirmation (`confirm = true`) and did not get it. */
    class ConfirmationRequired(what: String) : VaultSessionException("$what needs confirm = true")
}
