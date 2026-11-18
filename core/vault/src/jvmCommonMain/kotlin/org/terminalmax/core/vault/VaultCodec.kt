// SPDX-License-Identifier: GPL-3.0-or-later
@file:OptIn(ExperimentalSerializationApi::class)

package org.terminalmax.core.vault

import java.nio.CharBuffer
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.io.encoding.Base64
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters

/**
 * Reads and writes the binary vault file format v1 (see FORMAT.md).
 *
 * ```
 * "TMXV" | u16 version=1 | u32 headerLength | header (JSON, UTF-8) | AES-256-GCM ciphertext+tag
 * ```
 */
object VaultCodec {
    const val FORMAT_VERSION: Int = 1
    const val MAX_FILE_BYTES: Int = 32 * 1024 * 1024
    const val MAX_HEADER_BYTES: Int = 64 * 1024

    /** Id given to the first password slot created by [create]. */
    const val PASSWORD_SLOT_ID: String = "pw0"

    private const val KEY_BYTES = 32
    private const val NONCE_BYTES = 12
    private const val SALT_BYTES = 16
    private const val TAG_BYTES = 16
    private const val FIXED_PREFIX_BYTES = 10 // magic(4) + version(2) + headerLength(4)
    private const val MAX_SLOTS = 16
    private const val MAX_ID_CHARS = 128

    private val MAGIC = byteArrayOf(0x54, 0x4D, 0x58, 0x56) // "TMXV"
    private val VERSION_BYTES = byteArrayOf((FORMAT_VERSION shr 8).toByte(), FORMAT_VERSION.toByte())

    private val random = SecureRandom()
    private val b64 = Base64.Default
    private val headerWriter = Json {
        encodeDefaults = true
        explicitNulls = false
    }
    private val headerReader = Json {
        ignoreUnknownKeys = false
        explicitNulls = false
    }

    // ---------------------------------------------------------------- public API

    /** Creates a new, empty vault protected by [password]. [password] is not modified or retained. */
    fun create(
        password: CharArray,
        kdf: KdfParams = KdfParams.Default,
        vaultId: String = UUID.randomUUID().toString(),
    ): OpenVault {
        kdf.validate()
        require(vaultId.isNotEmpty() && vaultId.length <= MAX_ID_CHARS) { "Invalid vault id" }
        val dataKey = randomBytes(KEY_BYTES)
        try {
            val slot = newPasswordSlot(password, kdf, vaultId, PASSWORD_SLOT_ID, dataKey)
            val header = VaultHeader(
                vaultId = vaultId,
                slots = listOf(slot),
                contentNonce = b64.encode(ByteArray(NONCE_BYTES)), // replaced by a fresh nonce on every seal
            )
            return OpenVault(VaultContent.empty(vaultId), header, dataKey.copyOf())
        } finally {
            dataKey.fill(0)
        }
    }

    /** Opens [bytes] with the master [password]. [password] is not modified or retained. */
    fun open(bytes: ByteArray, password: CharArray): OpenVault {
        val parsed = parse(bytes)
        val passwordSlots = parsed.header.slots.filter { it.type == KeySlot.TYPE_PASSWORD }
        for (slot in passwordSlots) {
            val slotKey = deriveKey(password, b64.decode(slot.salt!!), slotParams(slot))
            val dataKey = try {
                unwrap(slotKey, slot, parsed.header.vaultId)
            } catch (e: VaultException.BadPasswordOrCorrupt) {
                null
            } finally {
                slotKey.fill(0)
            }
            if (dataKey != null) return finishOpen(parsed, dataKey)
        }
        throw VaultException.BadPasswordOrCorrupt()
    }

    /** Opens [bytes] using the device slot [slotId] and the caller-supplied 32-byte [deviceKey]. */
    fun openWithDeviceKey(bytes: ByteArray, slotId: String, deviceKey: ByteArray): OpenVault {
        require(deviceKey.size == KEY_BYTES) { "Device key must be 32 bytes" }
        val parsed = parse(bytes)
        val slot = parsed.header.slots.firstOrNull { it.id == slotId && it.type == KeySlot.TYPE_DEVICE }
            ?: throw VaultException.NoSuchSlot()
        val dataKey = unwrap(deviceKey, slot, parsed.header.vaultId)
        return finishOpen(parsed, dataKey)
    }

    /**
     * Opens [bytes] using the data key of an already open vault (used by sync to read the remote file without a
     * password). The remote header (which may have different slots) is adopted by the returned vault.
     *
     * @throws VaultException.DifferentVault when the file belongs to another vault
     */
    fun openWithDataKey(bytes: ByteArray, vault: OpenVault): OpenVault {
        val parsed = parse(bytes)
        if (parsed.header.vaultId != vault.vaultId) throw VaultException.DifferentVault()
        return finishOpen(parsed, vault.dataKey().copyOf())
    }

    /** Serialises and encrypts [vault] with a fresh random content nonce. */
    fun seal(vault: OpenVault): ByteArray {
        val content = vault.content
        if (content.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
            throw VaultException.UnsupportedVersion(content.schemaVersion, SUPPORTED_SCHEMA_VERSION)
        }
        check(content.vaultId == vault.vaultId) { "Content belongs to a different vault" }
        val nonce = randomBytes(NONCE_BYTES)
        val header = vault.header.copy(contentNonce = b64.encode(nonce))
        val headerBytes = headerWriter.encodeToString(VaultHeader.serializer(), header).toByteArray(Charsets.UTF_8)
        check(headerBytes.size <= MAX_HEADER_BYTES) { "Header too large" }
        val plaintext = VaultJson.encodeContent(content).toByteArray(Charsets.UTF_8)
        val ciphertext = try {
            gcmEncrypt(vault.dataKey(), nonce, contentAad(headerBytes), plaintext)
        } finally {
            plaintext.fill(0)
        }
        val out = ByteArray(FIXED_PREFIX_BYTES + headerBytes.size + ciphertext.size)
        MAGIC.copyInto(out, 0)
        VERSION_BYTES.copyInto(out, 4)
        writeU32(out, 6, headerBytes.size.toLong())
        headerBytes.copyInto(out, FIXED_PREFIX_BYTES)
        ciphertext.copyInto(out, FIXED_PREFIX_BYTES + headerBytes.size)
        check(out.size <= MAX_FILE_BYTES) { "Vault too large" }
        return out
    }

    /**
     * Re-wraps the data key under [newPassword], replacing only the (first) password slot. The data key and
     * all other slots are unchanged. [kdf] defaults to the parameters of the replaced slot.
     */
    fun changePassword(vault: OpenVault, newPassword: CharArray, kdf: KdfParams? = null): OpenVault {
        val old = vault.header.slots.firstOrNull { it.type == KeySlot.TYPE_PASSWORD }
        val params = kdf ?: old?.let { slotParams(it) } ?: KdfParams.Default
        params.validate()
        val slotId = old?.id ?: PASSWORD_SLOT_ID
        val slot = newPasswordSlot(newPassword, params, vault.vaultId, slotId, vault.dataKey())
        val slots = if (old == null) vault.header.slots + slot else vault.header.slots.map { if (it === old) slot else it }
        return OpenVault(vault.content, vault.header.copy(slots = slots), vault.dataKey().copyOf())
    }

    /** Adds a device slot [slotId] wrapped by the 32-byte [deviceKey]. */
    fun addDeviceSlot(vault: OpenVault, slotId: String, deviceKey: ByteArray): OpenVault {
        require(deviceKey.size == KEY_BYTES) { "Device key must be 32 bytes" }
        require(slotId.isNotEmpty() && slotId.length <= MAX_ID_CHARS) { "Invalid slot id" }
        require(vault.header.slots.none { it.id == slotId }) { "Slot id already exists" }
        require(vault.header.slots.size < MAX_SLOTS) { "Too many slots" }
        val nonce = randomBytes(NONCE_BYTES)
        val wrapped = gcmEncrypt(deviceKey, nonce, slotAad(vault.vaultId, slotId), vault.dataKey())
        val slot = KeySlot(
            id = slotId,
            type = KeySlot.TYPE_DEVICE,
            nonce = b64.encode(nonce),
            wrappedKey = b64.encode(wrapped),
        )
        return OpenVault(vault.content, vault.header.copy(slots = vault.header.slots + slot), vault.dataKey().copyOf())
    }

    /**
     * Removes a slot. At least one password slot must remain. Note: this does not rotate the data key, so
     * anyone who already holds the removed slot's key and an old copy of the file can still read that copy.
     */
    fun removeSlot(vault: OpenVault, slotId: String): OpenVault {
        val slots = vault.header.slots
        if (slots.none { it.id == slotId }) throw VaultException.NoSuchSlot()
        val remaining = slots.filterNot { it.id == slotId }
        require(remaining.any { it.type == KeySlot.TYPE_PASSWORD }) { "At least one password slot must remain" }
        return OpenVault(vault.content, vault.header.copy(slots = remaining), vault.dataKey().copyOf())
    }

    // ---------------------------------------------------------------- parsing

    private class Parsed(
        val header: VaultHeader,
        val headerBytes: ByteArray,
        val ciphertext: ByteArray,
        val contentNonce: ByteArray,
    )

    private fun parse(bytes: ByteArray): Parsed {
        if (bytes.size > MAX_FILE_BYTES) throw VaultException.InvalidFormat("file too large")
        if (bytes.size < FIXED_PREFIX_BYTES + TAG_BYTES) throw VaultException.InvalidFormat("file too short")
        if (!MessageDigest.isEqual(bytes.copyOfRange(0, 4), MAGIC)) throw VaultException.InvalidFormat("bad magic")
        val version = ((bytes[4].toInt() and 0xff) shl 8) or (bytes[5].toInt() and 0xff)
        if (version > FORMAT_VERSION) throw VaultException.UnsupportedVersion(version, FORMAT_VERSION)
        if (version != FORMAT_VERSION) throw VaultException.InvalidFormat("unknown format version")
        val headerLength = readU32(bytes, 6)
        if (headerLength < 2 || headerLength > MAX_HEADER_BYTES) {
            throw VaultException.InvalidFormat("bad header length")
        }
        val headerEnd = FIXED_PREFIX_BYTES + headerLength.toInt()
        if (headerEnd + TAG_BYTES > bytes.size) throw VaultException.InvalidFormat("file truncated")
        val headerBytes = bytes.copyOfRange(FIXED_PREFIX_BYTES, headerEnd)
        val ciphertext = bytes.copyOfRange(headerEnd, bytes.size)

        val header = try {
            headerReader.decodeFromString(VaultHeader.serializer(), String(headerBytes, Charsets.UTF_8))
        } catch (e: Exception) {
            throw VaultException.BadPasswordOrCorrupt(e)
        }
        val contentNonce = validateHeader(header)
        return Parsed(header, headerBytes, ciphertext, contentNonce)
    }

    /** Structural checks on an untrusted header; returns the decoded content nonce. */
    private fun validateHeader(h: VaultHeader): ByteArray {
        try {
            if (h.kdf != "argon2id") throw VaultException.BadPasswordOrCorrupt()
            if (h.vaultId.isEmpty() || h.vaultId.length > MAX_ID_CHARS) throw VaultException.BadPasswordOrCorrupt()
            if (h.slots.isEmpty() || h.slots.size > MAX_SLOTS) throw VaultException.BadPasswordOrCorrupt()
            if (h.slots.map { it.id }.toSet().size != h.slots.size) throw VaultException.BadPasswordOrCorrupt()
            for (s in h.slots) {
                if (s.id.isEmpty() || s.id.length > MAX_ID_CHARS) throw VaultException.BadPasswordOrCorrupt()
                if (b64.decode(s.nonce).size != NONCE_BYTES) throw VaultException.BadPasswordOrCorrupt()
                if (b64.decode(s.wrappedKey).size != KEY_BYTES + TAG_BYTES) throw VaultException.BadPasswordOrCorrupt()
                when (s.type) {
                    KeySlot.TYPE_PASSWORD -> {
                        if (s.salt == null || b64.decode(s.salt).size != SALT_BYTES) {
                            throw VaultException.BadPasswordOrCorrupt()
                        }
                        if (s.memoryKiB == null || s.iterations == null || s.parallelism == null) {
                            throw VaultException.BadPasswordOrCorrupt()
                        }
                        slotParams(s).validate() // before any key derivation runs
                    }
                    KeySlot.TYPE_DEVICE -> Unit
                    else -> throw VaultException.BadPasswordOrCorrupt()
                }
            }
            val nonce = b64.decode(h.contentNonce)
            if (nonce.size != NONCE_BYTES) throw VaultException.BadPasswordOrCorrupt()
            return nonce
        } catch (e: IllegalArgumentException) {
            throw VaultException.BadPasswordOrCorrupt(e) // invalid base64
        }
    }

    private fun slotParams(s: KeySlot): KdfParams = KdfParams(s.memoryKiB!!, s.iterations!!, s.parallelism!!)

    /** Decrypts the content with an already unwrapped [dataKey]; takes ownership of (and zeroes on failure) it. */
    private fun finishOpen(parsed: Parsed, dataKey: ByteArray): OpenVault {
        var plaintext: ByteArray? = null
        try {
            val aad = contentAad(parsed.headerBytes)
            plaintext = gcmDecrypt(dataKey, parsed.contentNonce, aad, parsed.ciphertext)
            val content = try {
                VaultJson.decodeContent(String(plaintext, Charsets.UTF_8))
            } catch (e: Exception) {
                throw VaultException.BadPasswordOrCorrupt(e)
            }
            if (content.vaultId != parsed.header.vaultId) throw VaultException.BadPasswordOrCorrupt()
            if (content.schemaVersion > SUPPORTED_SCHEMA_VERSION) {
                throw VaultException.UnsupportedVersion(content.schemaVersion, SUPPORTED_SCHEMA_VERSION)
            }
            return OpenVault(content, parsed.header, dataKey)
        } catch (e: Throwable) {
            dataKey.fill(0)
            throw e
        } finally {
            plaintext?.fill(0)
        }
    }

    // ---------------------------------------------------------------- slots and crypto

    private fun newPasswordSlot(
        password: CharArray,
        params: KdfParams,
        vaultId: String,
        slotId: String,
        dataKey: ByteArray,
    ): KeySlot {
        val salt = randomBytes(SALT_BYTES)
        val nonce = randomBytes(NONCE_BYTES)
        val slotKey = deriveKey(password, salt, params)
        try {
            val wrapped = gcmEncrypt(slotKey, nonce, slotAad(vaultId, slotId), dataKey)
            return KeySlot(
                id = slotId,
                type = KeySlot.TYPE_PASSWORD,
                salt = b64.encode(salt),
                memoryKiB = params.memoryKiB,
                iterations = params.iterations,
                parallelism = params.parallelism,
                nonce = b64.encode(nonce),
                wrappedKey = b64.encode(wrapped),
            )
        } finally {
            slotKey.fill(0)
        }
    }

    private fun unwrap(slotKey: ByteArray, slot: KeySlot, vaultId: String): ByteArray {
        val key = gcmDecrypt(slotKey, b64.decode(slot.nonce), slotAad(vaultId, slot.id), b64.decode(slot.wrappedKey))
        if (key.size != KEY_BYTES) {
            key.fill(0)
            throw VaultException.BadPasswordOrCorrupt()
        }
        return key
    }

    private fun deriveKey(password: CharArray, salt: ByteArray, params: KdfParams): ByteArray {
        params.validate()
        val passwordBytes = utf8(password)
        try {
            val argon = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withIterations(params.iterations)
                .withMemoryAsKB(params.memoryKiB)
                .withParallelism(params.parallelism)
                .withSalt(salt)
                .build()
            val generator = Argon2BytesGenerator()
            generator.init(argon)
            val out = ByteArray(KEY_BYTES)
            generator.generateBytes(passwordBytes, out, 0, out.size)
            return out
        } catch (e: OutOfMemoryError) {
            throw VaultException.KdfParamsOutOfRange("not enough memory for the requested cost")
        } finally {
            passwordBytes.fill(0)
        }
    }

    private fun utf8(chars: CharArray): ByteArray {
        val encoded = Charsets.UTF_8.encode(CharBuffer.wrap(chars))
        val bytes = ByteArray(encoded.remaining())
        encoded.get(bytes)
        if (encoded.hasArray()) encoded.array().fill(0)
        return bytes
    }

    private fun gcmEncrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    private fun gcmDecrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, ciphertext: ByteArray): ByteArray {
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_BYTES * 8, nonce))
            cipher.updateAAD(aad)
            return cipher.doFinal(ciphertext) // AEADBadTagException (a GeneralSecurityException) on mismatch
        } catch (e: GeneralSecurityException) {
            throw VaultException.BadPasswordOrCorrupt(e)
        }
    }

    /** AAD of the content ciphertext: magic || version || header bytes exactly as stored. */
    private fun contentAad(headerBytes: ByteArray): ByteArray = MAGIC + VERSION_BYTES + headerBytes

    /** AAD of a wrapped key: magic || version || len(vaultId) || vaultId || len(slotId) || slotId (u16 lengths). */
    private fun slotAad(vaultId: String, slotId: String): ByteArray {
        val v = vaultId.toByteArray(Charsets.UTF_8)
        val s = slotId.toByteArray(Charsets.UTF_8)
        return MAGIC + VERSION_BYTES + u16(v.size) + v + u16(s.size) + s
    }

    private fun u16(value: Int): ByteArray = byteArrayOf((value shr 8).toByte(), value.toByte())

    private fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

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
