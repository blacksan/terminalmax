// SPDX-License-Identifier: GPL-3.0-or-later
@file:OptIn(ExperimentalSerializationApi::class)

package org.terminalmax.core.vault

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.util.UUID
import kotlin.io.encoding.Base64
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json

/**
 * Reads and writes the binary vault file format v2 (see FORMAT.md). v1 does not exist as far as this code is
 * concerned: it is neither read nor written.
 *
 * ```
 * "TMXV" | u16 version=2 | u32 headerLength | header (JSON, UTF-8) | AES-256-GCM ciphertext+tag
 * ```
 *
 * Key management in one paragraph: a random 32-byte **data key** exists per **key epoch**; the single **password
 * slot** wraps it under an Argon2id key (there are no other slot types, see FORMAT.md). **The header is immutable
 * within a key epoch**: [changePassword] is the only way to change the slot (password or KDF parameters) and it
 * replaces the data key (epoch + 1) and links the new epoch to the old one with an HMAC under a key derived from
 * the old data key. Every write of the content uses a fresh content key derived from the data key (HKDF-SHA-256
 * with a random per-write salt). Every open verifies a commitment to the data key stored in the header.
 */
object VaultCodec {
    const val FORMAT_VERSION: Int = 2
    const val MAX_FILE_BYTES: Int = 8 * 1024 * 1024
    const val MAX_HEADER_BYTES: Int = 64 * 1024

    /** A vault has exactly one password slot (one Argon2id run per open, one guess per attacker-minted file). */
    const val MAX_PASSWORD_SLOTS: Int = 1

    private const val MAX_ID_CHARS = 128
    private const val MAX_KEY_EPOCH = 0xFFFF_FFFFL
    private const val FIXED_PREFIX_BYTES = 10 // magic(4) + version(2) + headerLength(4)
    private const val WRITE_SALT_BYTES = 32
    private const val UNLOCK_SECRET_VERSION = 1

    private val MAGIC = byteArrayOf(0x54, 0x4D, 0x58, 0x56) // "TMXV"
    private val UNLOCK_MAGIC = byteArrayOf(0x54, 0x4D, 0x58, 0x4B) // "TMXK"
    private val VERSION_BYTES = byteArrayOf((FORMAT_VERSION shr 8).toByte(), FORMAT_VERSION.toByte())
    private val INFO_CONTENT = "TMXV2 content".toByteArray(Charsets.UTF_8)
    private val INFO_COMMIT = "TMXV2 key commitment".toByteArray(Charsets.UTF_8)
    private val INFO_LINK_KEY = "TMXV2 epoch link key".toByteArray(Charsets.UTF_8)
    private val LINK_LABEL = "TMXV2 epoch link".toByteArray(Charsets.UTF_8)
    private val ZERO_NONCE = ByteArray(VaultCrypto.NONCE_BYTES)

    private val b64 = Base64.Default
    private val headerWriter = Json {
        encodeDefaults = true
        explicitNulls = false
    }
    private val headerReader = Json {
        ignoreUnknownKeys = false
        explicitNulls = false
    }

    // ---------------------------------------------------------------- public API: open / create / seal

    /**
     * Creates a new, empty vault protected by [password] (NFC-normalised, see FORMAT.md). [password] is not
     * modified or retained.
     *
     * @throws VaultException.KdfParamsOutOfRange / [VaultException.KdfCostTooHigh] for unacceptable [kdf]
     * @throws IllegalArgumentException when [password] is not valid UTF-16 or [vaultId] is malformed
     */
    fun create(
        password: CharArray,
        kdf: KdfParams = KdfParams.Default,
        vaultId: String = UUID.randomUUID().toString(),
    ): OpenVault {
        checkCostOfNewSlot(kdf)
        require(vaultId.isNotEmpty() && vaultId.length <= MAX_ID_CHARS) { "Invalid vault id" }
        val dataKey = VaultCrypto.randomBytes(VaultCrypto.KEY_BYTES)
        try {
            val slot = newPasswordSlot(password, kdf, vaultId, 1L, "pw-" + VaultCrypto.randomHex(8), dataKey)
            val header = VaultHeader(
                vaultId = vaultId,
                keyEpoch = 1L,
                slots = listOf(slot),
                writeSalt = b64.encode(ByteArray(WRITE_SALT_BYTES)), // replaced by a fresh salt on every seal
                keyCommit = b64.encode(keyCommit(dataKey, vaultId, 1L)),
                epochLink = null,
            )
            return OpenVault(VaultContent.empty(vaultId), header, dataKey.copyOf())
        } finally {
            dataKey.fill(0)
        }
    }

    /**
     * Opens [bytes] with the master [password] (NFC-normalised before use). [password] is not modified or
     * retained. The header is checked before any key derivation: exactly one password slot, within
     * [memoryCeilingKiB] and within the total cost budget. A slot that unwraps but whose key does not match the
     * header's key commitment is rejected (it is not an honest slot). An `OutOfMemoryError` during the derivation
     * is reported as [VaultException.KdfCostTooHigh].
     *
     * @throws VaultException.BadPasswordOrCorrupt wrong password, or the slot did not unwrap
     * @throws VaultException.IntegrityFailure the password was right but the content failed authentication
     * @throws VaultException.KdfCostTooHigh when the file asks for more key-derivation work than allowed
     * @throws IllegalArgumentException when [password] is not valid UTF-16 (an unpaired surrogate)
     */
    fun open(
        bytes: ByteArray,
        password: CharArray,
        memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
    ): OpenVault {
        val parsed = parse(bytes, memoryCeilingKiB)
        val slot = parsed.header.slots.single()
        val slotKey = VaultCrypto.argon2id(password, b64.decode(slot.salt), slotParams(slot))
        val dataKey = try {
            unwrap(slotKey, parsed.header, slot)
        } finally {
            slotKey.fill(0)
        }
        if (!commitMatches(parsed.header, dataKey)) {
            dataKey.fill(0)
            throw VaultException.BadPasswordOrCorrupt()
        }
        return finishOpen(parsed, dataKey, slotUnwrapped = true)
    }

    /**
     * Whether [password] unwraps the slot of [vault]'s own header (one Argon2id run, no content decryption). Used to
     * notice that a "re-key" kept the password (see FORMAT.md, rotation).
     */
    fun verifyPassword(
        vault: OpenVault,
        password: CharArray,
        memoryCeilingKiB: Int = KdfParams.PLATFORM_CEILING_KIB,
    ): Boolean {
        val slot = vault.header.slots.single()
        val params = slotParams(slot)
        params.validate()
        if (params.memoryKiB > memoryCeilingKiB) throw VaultException.KdfCostTooHigh("the slot asks for more memory than allowed")
        val slotKey = VaultCrypto.argon2id(password, b64.decode(slot.salt), params)
        try {
            unwrap(slotKey, vault.header, slot).fill(0)
            return true
        } catch (e: VaultException.BadPasswordOrCorrupt) {
            return false
        } finally {
            slotKey.fill(0)
        }
    }

    /**
     * Opens [bytes] with a secret produced by [OpenVault.exportLocalUnlockSecret] (per-device convenience unlock).
     * It succeeds only when the file is at the **same key epoch** as the secret and the key matches the header's
     * key commitment; no key derivation runs.
     *
     * @throws VaultException.KeyEpochMismatch the vault was re-keyed (any password change): ask for the password
     * @throws VaultException.BadPasswordOrCorrupt the secret is malformed, belongs to another vault or key, or the
     *   file was modified
     * @throws VaultException.IntegrityFailure the secret is right but the content failed authentication
     */
    fun openWithLocalUnlockSecret(bytes: ByteArray, secret: ByteArray): OpenVault {
        val decoded = decodeLocalUnlockSecret(secret) ?: throw VaultException.BadPasswordOrCorrupt()
        val dataKey = decoded.key
        try {
            val parsed = parse(bytes, KdfParams.MAX_MEMORY_KIB) // no key derivation runs on this path
            if (parsed.header.vaultId != decoded.vaultId) throw VaultException.BadPasswordOrCorrupt()
            if (parsed.header.keyEpoch != decoded.keyEpoch) {
                throw VaultException.KeyEpochMismatch(found = parsed.header.keyEpoch, expected = decoded.keyEpoch)
            }
            if (!commitMatches(parsed.header, dataKey)) throw VaultException.BadPasswordOrCorrupt()
            return finishOpen(parsed, dataKey.copyOf(), slotUnwrapped = true)
        } finally {
            dataKey.fill(0)
        }
    }

    /**
     * Opens [bytes] using the data key of an already open vault (used by sync to read the remote file without a
     * password). Only a file of the **same key epoch** and the **same key** can be read this way, and its header must
     * be byte-for-byte the header [vault] holds (apart from the write salt): within an epoch the header is immutable,
     * so a file that carries another one is refused before anything is decrypted. The returned vault holds the
     * header of [bytes], which is therefore the same as [vault]'s.
     *
     * @throws VaultException.DifferentVault when the file belongs to another vault
     * @throws VaultException.KeyEpochMismatch when the file is at another key epoch than [vault]
     * @throws VaultException.KeyMismatchSameEpoch when the file's key commitment is not [vault]'s key
     * @throws VaultException.HeaderMismatchSameEpoch when the key matches but the header differs from [vault]'s
     */
    fun openWithDataKey(bytes: ByteArray, vault: OpenVault): OpenVault {
        val parsed = parse(bytes, KdfParams.MAX_MEMORY_KIB) // no key derivation runs on this path
        if (parsed.header.vaultId != vault.vaultId) throw VaultException.DifferentVault()
        if (parsed.header.keyEpoch != vault.keyEpoch) {
            throw VaultException.KeyEpochMismatch(found = parsed.header.keyEpoch, expected = vault.keyEpoch)
        }
        if (!commitMatches(parsed.header, vault.dataKey())) throw VaultException.KeyMismatchSameEpoch()
        if (!parsed.header.sameKeyingAs(vault.header)) throw VaultException.HeaderMismatchSameEpoch()
        return finishOpen(parsed, vault.dataKey().copyOf(), slotUnwrapped = false)
    }

    /**
     * Whether the header of [bytes] is the header of [vault] (everything but the write salt), without any
     * cryptography. Used to recognise "this is the file my own password change produced".
     */
    fun hasSameHeaderAs(bytes: ByteArray, vault: OpenVault): Boolean =
        parse(bytes, KdfParams.MAX_MEMORY_KIB).header.sameKeyingAs(vault.header)

    /** Whether two files have the same header apart from the write salt (no cryptography). */
    fun haveSameHeader(a: ByteArray, b: ByteArray): Boolean =
        parse(a, KdfParams.MAX_MEMORY_KIB).header.sameKeyingAs(parse(b, KdfParams.MAX_MEMORY_KIB).header)

    /**
     * Checks whether [bytes] is the direct successor of the epoch that [previous] holds: exactly one epoch higher,
     * with an `epochLink` that verifies under a key derived from [previous]'s data key. Only someone who held that
     * key could have produced a valid link, so a [EpochLinkStatus.Verified] file was re-keyed by a holder of
     * [previous]'s epoch. Nothing is decrypted. The link covers the vault id, the new epoch and the commitment to the
     * new key, not the slots (see FORMAT.md).
     *
     * @throws VaultException.DifferentVault when the file belongs to another vault
     */
    fun verifyEpochLink(bytes: ByteArray, previous: OpenVault): EpochLinkStatus {
        val header = parse(bytes, KdfParams.MAX_MEMORY_KIB).header
        if (header.vaultId != previous.vaultId) throw VaultException.DifferentVault()
        if (header.keyEpoch <= previous.keyEpoch) return EpochLinkStatus.NotApplicable
        val link = header.epochLink
        if (header.keyEpoch != previous.keyEpoch + 1L || link == null) return EpochLinkStatus.Unverified
        val expected = epochLinkMac(
            previous.dataKey(), header.vaultId, previous.keyEpoch, header.keyEpoch, b64.decode(header.keyCommit),
        )
        return if (MessageDigest.isEqual(expected, b64.decode(link))) EpochLinkStatus.Verified else EpochLinkStatus.Unverified
    }

    /**
     * Reads the structural facts of a file's header without any cryptography. **Nothing returned is
     * authenticated**; use it to decide which key to try, then rely on the values of the opened vault.
     */
    fun inspect(bytes: ByteArray): HeaderInfo {
        val h = parse(bytes, KdfParams.MAX_MEMORY_KIB).header
        return HeaderInfo(h.vaultId, h.keyEpoch, h.slots.map { SlotInfo(it.id, it.type) })
    }

    /**
     * Serialises and encrypts [vault] with a fresh random write salt (and therefore a fresh content key).
     *
     * @throws VaultException.InvalidContent when the content breaks the content rules or the file would exceed
     *   [MAX_FILE_BYTES]
     * @throws VaultException.UnsupportedVersion when the content uses a newer schema
     */
    fun seal(vault: OpenVault): ByteArray = sealInternal(vault, validateContent = true)

    /** Seals without the content rules; exists so tests can produce authentic-but-invalid files. */
    internal fun sealWithoutContentValidation(vault: OpenVault): ByteArray = sealInternal(vault, validateContent = false)

    private fun sealInternal(vault: OpenVault, validateContent: Boolean): ByteArray {
        val content = vault.content
        if (content.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
            throw VaultException.UnsupportedVersion(content.schemaVersion, SUPPORTED_SCHEMA_VERSION)
        }
        if (content.schemaVersion != SUPPORTED_SCHEMA_VERSION) throw VaultException.InvalidContent("schema version")
        if (content.vaultId != vault.vaultId) throw VaultException.InvalidContent("content belongs to another vault")
        if (validateContent) content.validate()
        val writeSalt = VaultCrypto.randomBytes(WRITE_SALT_BYTES)
        val header = vault.header.copy(writeSalt = b64.encode(writeSalt))
        val headerBytes = headerWriter.encodeToString(VaultHeader.serializer(), header).toByteArray(Charsets.UTF_8)
        if (headerBytes.size > MAX_HEADER_BYTES) throw VaultException.InvalidContent("header too large")
        val plaintext = VaultJson.encodeContentWithEpoch(content, header.keyEpoch).toByteArray(Charsets.UTF_8)
        val contentKey = deriveContentKey(vault.dataKey(), writeSalt, header.keyEpoch)
        val ciphertext = try {
            VaultCrypto.gcmEncrypt(contentKey, ZERO_NONCE, contentAad(headerBytes), plaintext)
        } finally {
            plaintext.fill(0)
            contentKey.fill(0)
        }
        val total = FIXED_PREFIX_BYTES.toLong() + headerBytes.size + ciphertext.size
        if (total > MAX_FILE_BYTES) throw VaultException.InvalidContent("vault file too large")
        val out = ByteArray(total.toInt())
        MAGIC.copyInto(out, 0)
        VERSION_BYTES.copyInto(out, 4)
        writeU32(out, 6, headerBytes.size.toLong())
        headerBytes.copyInto(out, FIXED_PREFIX_BYTES)
        ciphertext.copyInto(out, FIXED_PREFIX_BYTES + headerBytes.size)
        return out
    }

    // ---------------------------------------------------------------- public API: rotation

    /**
     * Replaces the password (and, with [kdf], the key-derivation parameters) **and replaces the data key**: the old
     * password, together with any old copy of the file, can no longer open anything written afterwards. This is the
     * only way to change the password slot: the header never changes within a key epoch. The key epoch increases by
     * one (or to [atLeastEpoch] when that is higher, for a replacement that must outrank a foreign epoch) and the new
     * epoch is linked to the old one. [kdf] defaults to the parameters of the replaced slot.
     *
     * The returned vault owns a new key; the caller closes [vault] (it still holds the old key).
     */
    fun changePassword(
        vault: OpenVault,
        newPassword: CharArray,
        kdf: KdfParams? = null,
        atLeastEpoch: Long = 0L,
    ): OpenVault {
        val target = vault.header.slots.single()
        val params = kdf ?: slotParams(target)
        checkCostOfNewSlot(params)
        val header = vault.header
        if (header.keyEpoch >= MAX_KEY_EPOCH) throw VaultException.InvalidContent("key epoch limit reached")
        val newEpoch = maxOf(header.keyEpoch + 1L, atLeastEpoch)
        if (newEpoch > MAX_KEY_EPOCH) throw VaultException.InvalidContent("key epoch limit reached")
        val newKey = VaultCrypto.randomBytes(VaultCrypto.KEY_BYTES)
        try {
            val slot = newPasswordSlot(newPassword, params, header.vaultId, newEpoch, target.id, newKey)
            val newCommit = keyCommit(newKey, header.vaultId, newEpoch)
            val link = epochLinkMac(vault.dataKey(), header.vaultId, header.keyEpoch, newEpoch, newCommit)
            val updated = header.copy(
                keyEpoch = newEpoch,
                slots = listOf(slot),
                keyCommit = b64.encode(newCommit),
                epochLink = b64.encode(link),
            )
            return OpenVault(vault.content, updated, newKey.copyOf())
        } finally {
            newKey.fill(0)
        }
    }

    /**
     * The escape hatch for a vault that cannot be edited any more (for example its revisions reached the limit):
     * a **new vault id**, protected by [newPassword], holding the live (not deleted) records of [vault] at revision 1.
     * Tombstones and history are dropped. Every device must then enrol in the new vault; the old one is abandoned.
     */
    fun migrateToNewVault(
        vault: OpenVault,
        newPassword: CharArray,
        kdf: KdfParams = KdfParams.Default,
        vaultId: String = UUID.randomUUID().toString(),
    ): OpenVault {
        val fresh = create(newPassword, kdf, vaultId)
        try {
            val records = vault.content.records.filterNot { it.deleted }.map { it.copy(revision = 1L) }
            val content = VaultContent(
                schemaVersion = SUPPORTED_SCHEMA_VERSION,
                vaultId = vaultId,
                revision = if (records.isEmpty()) 0L else 1L,
                records = records,
            )
            content.validate()
            return fresh.withContent(content)
        } finally {
            fresh.close()
        }
    }

    // ---------------------------------------------------------------- local unlock secret

    internal fun encodeLocalUnlockSecret(vaultId: String, keyEpoch: Long, dataKey: ByteArray): ByteArray {
        val id = vaultId.toByteArray(Charsets.UTF_8)
        val out = ByteArray(UNLOCK_MAGIC.size + 1 + 4 + 2 + id.size + dataKey.size) // pre-sized: no stray copy of the key
        UNLOCK_MAGIC.copyInto(out, 0)
        out[4] = UNLOCK_SECRET_VERSION.toByte()
        writeU32(out, 5, keyEpoch)
        out[9] = (id.size shr 8).toByte()
        out[10] = id.size.toByte()
        id.copyInto(out, 11)
        dataKey.copyInto(out, 11 + id.size)
        return out // the caller zeroes it
    }

    private class UnlockSecret(val keyEpoch: Long, val vaultId: String, val key: ByteArray)

    private fun decodeLocalUnlockSecret(secret: ByteArray): UnlockSecret? {
        if (secret.size < UNLOCK_MAGIC.size + 1 + 4 + 2 + VaultCrypto.KEY_BYTES) return null
        if (!MessageDigest.isEqual(secret.copyOfRange(0, 4), UNLOCK_MAGIC)) return null
        if (secret[4].toInt() != UNLOCK_SECRET_VERSION) return null
        val epoch = readU32(secret, 5)
        val idLength = ((secret[9].toInt() and 0xff) shl 8) or (secret[10].toInt() and 0xff)
        if (idLength == 0 || idLength > MAX_ID_CHARS * 4) return null
        if (secret.size != 11 + idLength + VaultCrypto.KEY_BYTES) return null
        val vaultId = try {
            Charsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(secret, 11, idLength))
                .toString()
        } catch (e: CharacterCodingException) {
            return null
        }
        return UnlockSecret(epoch, vaultId, secret.copyOfRange(11 + idLength, secret.size))
    }

    // ---------------------------------------------------------------- parsing

    private class Parsed(
        val header: VaultHeader,
        val headerBytes: ByteArray,
        val ciphertext: ByteArray,
        val writeSalt: ByteArray,
    )

    private fun parse(bytes: ByteArray, memoryCeilingKiB: Int): Parsed {
        if (bytes.size > MAX_FILE_BYTES) throw VaultException.InvalidFormat("file too large")
        if (bytes.size < FIXED_PREFIX_BYTES + VaultCrypto.TAG_BYTES) throw VaultException.InvalidFormat("file too short")
        if (!MessageDigest.isEqual(bytes.copyOfRange(0, 4), MAGIC)) throw VaultException.InvalidFormat("bad magic")
        val version = ((bytes[4].toInt() and 0xff) shl 8) or (bytes[5].toInt() and 0xff)
        if (version > FORMAT_VERSION) throw VaultException.UnsupportedVersion(version, FORMAT_VERSION)
        if (version != FORMAT_VERSION) throw VaultException.InvalidFormat("format version $version is not supported")
        val headerLength = readU32(bytes, 6)
        if (headerLength < 2 || headerLength > MAX_HEADER_BYTES) {
            throw VaultException.InvalidFormat("bad header length")
        }
        val headerEnd = FIXED_PREFIX_BYTES + headerLength.toInt()
        if (headerEnd + VaultCrypto.TAG_BYTES > bytes.size) throw VaultException.InvalidFormat("file truncated")
        val headerBytes = bytes.copyOfRange(FIXED_PREFIX_BYTES, headerEnd)
        val ciphertext = bytes.copyOfRange(headerEnd, bytes.size)

        val header = try {
            headerReader.decodeFromString(VaultHeader.serializer(), String(headerBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            throw VaultException.BadPasswordOrCorrupt(e)
        }
        val writeSalt = validateHeader(header, memoryCeilingKiB)
        return Parsed(header, headerBytes, ciphertext, writeSalt)
    }

    /**
     * Structural checks on an untrusted header, done before any key derivation: the limits on slots and on the
     * total key-derivation cost are enforced here. Returns the decoded write salt.
     */
    private fun validateHeader(h: VaultHeader, memoryCeilingKiB: Int): ByteArray {
        try {
            if (h.kdf != "argon2id") throw VaultException.BadPasswordOrCorrupt()
            if (h.vaultId.isEmpty() || h.vaultId.length > MAX_ID_CHARS) throw VaultException.BadPasswordOrCorrupt()
            if (h.keyEpoch !in 1L..MAX_KEY_EPOCH) throw VaultException.BadPasswordOrCorrupt()
            if (b64.decode(h.keyCommit).size != VaultCrypto.KEY_BYTES) throw VaultException.BadPasswordOrCorrupt()
            val link = h.epochLink
            if ((h.keyEpoch == 1L) != (link == null)) throw VaultException.BadPasswordOrCorrupt()
            if (link != null && b64.decode(link).size != VaultCrypto.KEY_BYTES) throw VaultException.BadPasswordOrCorrupt()
            if (h.slots.size != MAX_PASSWORD_SLOTS) {
                throw VaultException.InvalidFormat("a vault has exactly one password slot, found ${h.slots.size}")
            }
            var totalCost = 0L
            for (s in h.slots) {
                if (s.id.isEmpty() || s.id.length > MAX_ID_CHARS) throw VaultException.BadPasswordOrCorrupt()
                if (s.type != SlotTypes.PASSWORD) throw VaultException.BadPasswordOrCorrupt()
                if (b64.decode(s.nonce).size != VaultCrypto.NONCE_BYTES) throw VaultException.BadPasswordOrCorrupt()
                if (b64.decode(s.wrappedKey).size != VaultCrypto.KEY_BYTES + VaultCrypto.TAG_BYTES) {
                    throw VaultException.BadPasswordOrCorrupt()
                }
                if (b64.decode(s.salt).size != VaultCrypto.SALT_BYTES) throw VaultException.BadPasswordOrCorrupt()
            }
            for (s in h.slots) {
                val params = slotParams(s)
                params.validate()
                if (params.memoryKiB > memoryCeilingKiB) {
                    throw VaultException.KdfCostTooHigh("a slot asks for more memory than this device allows")
                }
                totalCost += params.cost
            }
            if (totalCost > KdfParams.MAX_TOTAL_COST) throw VaultException.KdfCostTooHigh("total key-derivation cost")
            val salt = b64.decode(h.writeSalt)
            if (salt.size != WRITE_SALT_BYTES) throw VaultException.BadPasswordOrCorrupt()
            return salt
        } catch (e: IllegalArgumentException) {
            throw VaultException.BadPasswordOrCorrupt(e) // invalid base64
        }
    }

    private fun slotParams(s: KeySlot): KdfParams = KdfParams(s.memoryKiB, s.iterations, s.parallelism)

    /**
     * Decrypts the content with an already unwrapped [dataKey]; takes ownership of (and zeroes on failure) it.
     * [slotUnwrapped] says that a key slot or a verified secret accepted the key, so a content failure means
     * tampering, not a wrong key.
     */
    private fun finishOpen(parsed: Parsed, dataKey: ByteArray, slotUnwrapped: Boolean): OpenVault {
        var plaintext: ByteArray? = null
        var contentKey: ByteArray? = null
        try {
            contentKey = deriveContentKey(dataKey, parsed.writeSalt, parsed.header.keyEpoch)
            plaintext = try {
                VaultCrypto.gcmDecrypt(contentKey, ZERO_NONCE, contentAad(parsed.headerBytes), parsed.ciphertext)
            } catch (e: GeneralSecurityException) {
                throw if (slotUnwrapped) VaultException.IntegrityFailure(e) else VaultException.BadPasswordOrCorrupt(e)
            }
            val decoded = try {
                VaultJson.decodeContentWithEpoch(String(plaintext, Charsets.UTF_8))
            } catch (e: Exception) {
                throw VaultException.InvalidContent("content cannot be decoded")
            }
            val content = decoded.first
            if (decoded.second != parsed.header.keyEpoch) throw VaultException.InvalidContent("key epoch mismatch")
            if (content.vaultId != parsed.header.vaultId) throw VaultException.InvalidContent("vault id mismatch")
            if (content.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
                throw VaultException.UnsupportedVersion(content.schemaVersion, SUPPORTED_SCHEMA_VERSION)
            }
            if (content.schemaVersion != SUPPORTED_SCHEMA_VERSION) throw VaultException.InvalidContent("schema version")
            content.validate()
            return OpenVault(content, parsed.header, dataKey)
        } catch (e: Throwable) {
            dataKey.fill(0)
            throw e
        } finally {
            plaintext?.fill(0)
            contentKey?.fill(0)
        }
    }

    // ---------------------------------------------------------------- slots and crypto

    /** Rejects [params] that are out of bounds, above the platform ceiling or that blow the per-file budget. */
    private fun checkCostOfNewSlot(params: KdfParams) {
        params.validate()
        if (params.memoryKiB > KdfParams.PLATFORM_CEILING_KIB) {
            throw VaultException.KdfCostTooHigh("memory above the platform ceiling")
        }
        if (params.cost > KdfParams.MAX_TOTAL_COST) {
            throw VaultException.KdfCostTooHigh("total key-derivation cost of the password slot")
        }
    }

    private fun newPasswordSlot(
        password: CharArray,
        params: KdfParams,
        vaultId: String,
        keyEpoch: Long,
        slotId: String,
        dataKey: ByteArray,
    ): KeySlot {
        val salt = VaultCrypto.randomBytes(VaultCrypto.SALT_BYTES)
        val slotKey = VaultCrypto.argon2id(password, salt, params)
        try {
            return passwordSlotWithKey(slotKey, salt, params, vaultId, keyEpoch, slotId, dataKey)
        } finally {
            slotKey.fill(0)
        }
    }

    private fun passwordSlotWithKey(
        slotKey: ByteArray,
        salt: ByteArray,
        params: KdfParams,
        vaultId: String,
        keyEpoch: Long,
        slotId: String,
        dataKey: ByteArray,
    ): KeySlot {
        val nonce = VaultCrypto.randomBytes(VaultCrypto.NONCE_BYTES)
        val unsealed = KeySlot(
            id = slotId,
            type = SlotTypes.PASSWORD,
            salt = b64.encode(salt),
            memoryKiB = params.memoryKiB,
            iterations = params.iterations,
            parallelism = params.parallelism,
            nonce = b64.encode(nonce),
            wrappedKey = "",
        )
        val wrapped = VaultCrypto.gcmEncrypt(slotKey, nonce, slotAad(vaultId, keyEpoch, unsealed), dataKey)
        return unsealed.copy(wrappedKey = b64.encode(wrapped))
    }

    private fun unwrap(slotKey: ByteArray, header: VaultHeader, slot: KeySlot): ByteArray {
        val key = try {
            VaultCrypto.gcmDecrypt(
                slotKey,
                b64.decode(slot.nonce),
                slotAad(header.vaultId, header.keyEpoch, slot),
                b64.decode(slot.wrappedKey),
            )
        } catch (e: GeneralSecurityException) {
            throw VaultException.BadPasswordOrCorrupt(e)
        }
        if (key.size != VaultCrypto.KEY_BYTES) {
            key.fill(0)
            throw VaultException.BadPasswordOrCorrupt()
        }
        return key
    }

    /** Key commitment = HKDF-SHA-256(dataKey, salt = vaultId, info = "TMXV2 key commitment" || u32(keyEpoch), 32). */
    private fun keyCommit(dataKey: ByteArray, vaultId: String, keyEpoch: Long): ByteArray {
        val info = ByteArrayOutputStream()
        info.write(INFO_COMMIT)
        writeU32(info, keyEpoch)
        return VaultCrypto.hkdf(dataKey, vaultId.toByteArray(Charsets.UTF_8), info.toByteArray(), VaultCrypto.KEY_BYTES)
    }

    private fun commitMatches(header: VaultHeader, dataKey: ByteArray): Boolean {
        val expected = keyCommit(dataKey, header.vaultId, header.keyEpoch)
        return MessageDigest.isEqual(expected, b64.decode(header.keyCommit))
    }

    /**
     * `linkKey = HKDF-SHA-256(previousKey, salt = vaultId, info = "TMXV2 epoch link key" || u32(previousEpoch), 32)` and
     * `link = HMAC-SHA-256(linkKey, "TMXV2 epoch link" || lp(vaultId) || u32(newEpoch) || newKeyCommit)`.
     */
    private fun epochLinkMac(
        previousKey: ByteArray,
        vaultId: String,
        previousEpoch: Long,
        newEpoch: Long,
        newKeyCommit: ByteArray,
    ): ByteArray {
        val info = ByteArrayOutputStream()
        info.write(INFO_LINK_KEY)
        writeU32(info, previousEpoch)
        val linkKey = VaultCrypto.hkdf(previousKey, vaultId.toByteArray(Charsets.UTF_8), info.toByteArray(), VaultCrypto.KEY_BYTES)
        try {
            val message = ByteArrayOutputStream()
            message.write(LINK_LABEL)
            writeLp(message, vaultId)
            writeU32(message, newEpoch)
            message.write(newKeyCommit)
            return VaultCrypto.hmacSha256(linkKey, message.toByteArray())
        } finally {
            linkKey.fill(0)
        }
    }

    /** Content key = HKDF-SHA-256(dataKey, salt = write salt, info = "TMXV2 content" || u32(keyEpoch)). */
    private fun deriveContentKey(dataKey: ByteArray, writeSalt: ByteArray, keyEpoch: Long): ByteArray {
        val info = ByteArrayOutputStream()
        info.write(INFO_CONTENT)
        writeU32(info, keyEpoch)
        return VaultCrypto.hkdf(dataKey, writeSalt, info.toByteArray(), VaultCrypto.KEY_BYTES)
    }

    /** AAD of the content ciphertext: magic || version || header bytes exactly as stored. */
    private fun contentAad(headerBytes: ByteArray): ByteArray = MAGIC + VERSION_BYTES + headerBytes

    /**
     * AAD of a wrapped key: magic || version || lp(vaultId) || u32(keyEpoch) || lp(slotId) || lp(type) || salt ||
     * u32(memoryKiB) || u32(iterations) || u32(parallelism).
     */
    private fun slotAad(vaultId: String, keyEpoch: Long, slot: KeySlot): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(MAGIC)
        out.write(VERSION_BYTES)
        writeLp(out, vaultId)
        writeU32(out, keyEpoch)
        writeLp(out, slot.id)
        writeLp(out, slot.type)
        out.write(b64.decode(slot.salt))
        writeU32(out, slot.memoryKiB.toLong())
        writeU32(out, slot.iterations.toLong())
        writeU32(out, slot.parallelism.toLong())
        return out.toByteArray()
    }

    private fun writeLp(out: ByteArrayOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        out.write(bytes.size shr 8)
        out.write(bytes.size)
        out.write(bytes)
    }

    private fun writeU32(out: ByteArrayOutputStream, value: Long) {
        out.write((value shr 24).toInt())
        out.write((value shr 16).toInt())
        out.write((value shr 8).toInt())
        out.write(value.toInt())
    }

    private fun readU32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xff) shl 24) or ((b[off + 1].toLong() and 0xff) shl 16) or
            ((b[off + 2].toLong() and 0xff) shl 8) or (b[off + 3].toLong() and 0xff)

    private fun writeU32(b: ByteArray, off: Int, value: Long) {
        b[off] = (value shr 24).toByte()
        b[off + 1] = (value shr 16).toByte()
        b[off + 2] = (value shr 8).toByte()
        b[off + 3] = value.toByte()
    }
}
