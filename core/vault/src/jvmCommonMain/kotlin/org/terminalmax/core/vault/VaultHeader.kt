// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlinx.serialization.Serializable

/** Slot type names as they appear in the header JSON. Format v2 has password slots only. */
object SlotTypes {
    const val PASSWORD: String = "password"
}

/**
 * One key slot: the data key wrapped (AES-256-GCM) under an Argon2id key derived from a password. There are no
 * other slot types: a public-key slot would let anyone who can read the cleartext header mint a new key epoch that
 * honest devices adopt (see FORMAT.md).
 */
@Serializable
internal data class KeySlot(
    val id: String,
    val type: String,
    val salt: String,
    val memoryKiB: Int,
    val iterations: Int,
    val parallelism: Int,
    val nonce: String,
    val wrappedKey: String,
)

/**
 * @property keyCommit commitment to the data key of [keyEpoch] (base64, 32 bytes); every open verifies it
 * @property epochLink for [keyEpoch] >= 2: HMAC-SHA-256 under a key derived from the previous epoch's data key,
 *   proving that whoever wrote this epoch held the previous key (base64, 32 bytes); null for epoch 1
 */
@Serializable
internal data class VaultHeader(
    val kdf: String = "argon2id",
    val vaultId: String,
    val keyEpoch: Long,
    val headerRevision: Long,
    val slots: List<KeySlot>,
    val writeSalt: String,
    val keyCommit: String,
    val epochLink: String? = null,
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

/** Result of [VaultCodec.verifyEpochLink]. */
enum class EpochLinkStatus {
    /** The file is exactly one epoch above the key that was offered and its link verifies under that key. */
    Verified,

    /** The file is above the offered key's epoch but cannot be linked to it (bad link, or more than one epoch ahead). */
    Unverified,

    /** The file is not above the offered key's epoch, so there is no link to check. */
    NotApplicable,
}
