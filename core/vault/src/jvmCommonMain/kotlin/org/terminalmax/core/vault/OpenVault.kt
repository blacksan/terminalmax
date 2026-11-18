// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

/**
 * A decrypted vault: its [content] plus the (secret) data key needed to re-seal it. Call [close] when done; it
 * zeroes the key bytes. Instances produced by [withContent] and the codec's slot operations own independent
 * copies of the key and must be closed separately.
 *
 * Note: [content] itself is ordinary heap data (strings) and cannot be zeroed.
 */
class OpenVault internal constructor(
    val content: VaultContent,
    internal val header: VaultHeader,
    dataKey: ByteArray,
) : AutoCloseable {
    private val key: ByteArray = dataKey

    @Volatile
    private var closed = false

    val vaultId: String get() = header.vaultId

    /** Ids of all key slots in the header. */
    val slotIds: List<String> get() = header.slots.map { it.id }

    /** A new [OpenVault] with the same key and header but different [newContent]. */
    fun withContent(newContent: VaultContent): OpenVault {
        require(newContent.vaultId == vaultId) { "Content belongs to a different vault" }
        return OpenVault(newContent, header, dataKey().copyOf())
    }

    internal fun dataKey(): ByteArray {
        check(!closed) { "Vault is closed" }
        return key
    }

    override fun close() {
        closed = true
        key.fill(0)
    }

    override fun toString(): String = "OpenVault(vaultId=$vaultId, revision=${content.revision})"
}
