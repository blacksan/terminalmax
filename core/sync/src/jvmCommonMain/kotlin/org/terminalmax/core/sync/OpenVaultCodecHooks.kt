// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import org.terminalmax.core.vault.OpenVault
import org.terminalmax.core.vault.VaultCodec
import org.terminalmax.core.vault.VaultContent

/**
 * [VaultCodecHooks] backed by an [OpenVault] (which holds the data key). Remote files are opened with the data
 * key, so no password is needed during sync.
 *
 * By default an upload keeps the key slots of the remote file it replaces, so a password change or device slot
 * made on another device is not undone. Set [useLocalHeader] after changing slots locally (changePassword,
 * addDeviceSlot, removeSlot) so the next upload carries this device's slots; clear it once that upload succeeded.
 *
 * The caller owns [vault] and closes it.
 */
class OpenVaultCodecHooks(private val vault: OpenVault) : VaultCodecHooks {
    @Volatile
    var useLocalHeader: Boolean = false

    override fun decrypt(bytes: ByteArray): VaultContent {
        val opened = VaultCodec.openWithDataKey(bytes, vault)
        try {
            return opened.content
        } finally {
            opened.close()
        }
    }

    override fun encrypt(content: VaultContent, replacing: ByteArray?): ByteArray {
        if (replacing == null || useLocalHeader) {
            val local = vault.withContent(content)
            try {
                return VaultCodec.seal(local)
            } finally {
                local.close()
            }
        }
        val remote = VaultCodec.openWithDataKey(replacing, vault)
        try {
            val updated = remote.withContent(content)
            try {
                return VaultCodec.seal(updated)
            } finally {
                updated.close()
            }
        } finally {
            remote.close()
        }
    }
}

/** Wall-clock milliseconds, for [SyncEngine]'s `clock` parameter. */
fun systemClockMillis(): Long = System.currentTimeMillis()
