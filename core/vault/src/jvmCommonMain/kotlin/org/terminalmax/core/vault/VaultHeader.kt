// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlinx.serialization.Serializable

/** Slot type names as they appear in the header JSON. */
object SlotTypes {
    const val PASSWORD: String = "password"
    const val DEVICE_X25519: String = "device-x25519"
}

/**
 * One key slot. A "password" slot wraps the data key under an Argon2id-derived key; a "device-x25519" slot wraps it
 * to a device's X25519 public key (ephemeral-static Diffie-Hellman + HKDF-SHA-256), so any holder of the data key
 * can wrap a new data key for that device without holding its private key. Fields that do not apply to a slot type
 * are null (and omitted in JSON).
 */
@Serializable
internal data class KeySlot(
    val id: String,
    val type: String,
    val salt: String? = null,
    val memoryKiB: Int? = null,
    val iterations: Int? = null,
    val parallelism: Int? = null,
    val devicePublicKey: String? = null,
    val ephemeralPublicKey: String? = null,
    val nonce: String,
    val wrappedKey: String,
)

@Serializable
internal data class VaultHeader(
    val kdf: String = "argon2id",
    val vaultId: String,
    val keyEpoch: Long,
    val headerRevision: Long,
    val slots: List<KeySlot>,
    val writeSalt: String,
)

/** Public description of a key slot. */
data class SlotInfo(val id: String, val type: String)

/**
 * The structural facts of a vault file's header. Obtained from [VaultCodec.inspect] **without any cryptography**,
 * so nothing here is authenticated; use it only to choose which key to try. [OpenVault.keyEpoch] and
 * [OpenVault.headerRevision] of an opened vault are the authenticated values.
 */
data class HeaderInfo(
    val vaultId: String,
    val keyEpoch: Long,
    val headerRevision: Long,
    val slots: List<SlotInfo>,
)
