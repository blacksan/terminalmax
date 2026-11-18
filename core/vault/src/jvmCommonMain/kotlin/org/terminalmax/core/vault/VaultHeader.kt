// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlinx.serialization.Serializable

/**
 * One key slot. A "password" slot wraps the data key under an Argon2id-derived key; a "device" slot wraps it
 * under a caller-supplied 32-byte key. Fields that do not apply to a slot type are null (and omitted in JSON).
 */
@Serializable
internal data class KeySlot(
    val id: String,
    val type: String,
    val salt: String? = null,
    val memoryKiB: Int? = null,
    val iterations: Int? = null,
    val parallelism: Int? = null,
    val nonce: String,
    val wrappedKey: String,
) {
    companion object {
        const val TYPE_PASSWORD = "password"
        const val TYPE_DEVICE = "device"
    }
}

@Serializable
internal data class VaultHeader(
    val kdf: String = "argon2id",
    val vaultId: String,
    val slots: List<KeySlot>,
    val contentNonce: String,
)
