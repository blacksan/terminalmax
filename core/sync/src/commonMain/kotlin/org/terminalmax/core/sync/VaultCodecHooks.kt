// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.VaultContent

/**
 * The encryption side of sync, kept behind an interface so the engine is pure Kotlin. Both methods throw
 * [org.terminalmax.core.vault.VaultException] on failure.
 */
interface VaultCodecHooks {
    /** Decrypts and parses a remote vault file. */
    fun decrypt(bytes: ByteArray): VaultContent

    /**
     * Encrypts [content] into a vault file. [replacing] is the remote file being replaced (null for the first
     * upload); implementations keep its key slots so slot changes made on other devices are not lost.
     */
    fun encrypt(content: VaultContent, replacing: ByteArray?): ByteArray
}
