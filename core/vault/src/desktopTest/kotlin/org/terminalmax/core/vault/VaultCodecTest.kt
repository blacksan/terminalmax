// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import java.security.SecureRandom
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class VaultCodecTest {
    /** Smallest accepted cost, so the suite stays fast. */
    private val fast = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)
    private val password = "correct horse battery staple"

    private fun pw(value: String = password) = value.toCharArray()

    private fun deviceKey(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun sampleVault(): OpenVault {
        val created = VaultCodec.create(pw(), fast)
        val editor = VaultEditor(created.content, "dev-A")
        editor.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin"), id = "h1")
        editor.upsertIdentity(IdentityPayload("root", "root", password = "s3cret"), id = "i1")
        editor.upsertSnippet(SnippetPayload("s", "uptime"), id = "s1")
        return created.withContent(editor.content).also { created.close() }
    }

    private fun readU32(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 24) or ((b[off + 1].toInt() and 0xff) shl 16) or
            ((b[off + 2].toInt() and 0xff) shl 8) or (b[off + 3].toInt() and 0xff)

    private fun headerLength(bytes: ByteArray) = readU32(bytes, 6)

    private fun headerText(bytes: ByteArray) = String(bytes, 10, headerLength(bytes), Charsets.UTF_8)

    /** Re-frames [bytes] with a modified header (ciphertext untouched). */
    private fun withHeader(bytes: ByteArray, transform: (String) -> String): ByteArray {
        val newHeader = transform(headerText(bytes)).toByteArray(Charsets.UTF_8)
        val ciphertext = bytes.copyOfRange(10 + headerLength(bytes), bytes.size)
        val out = ByteArray(10 + newHeader.size + ciphertext.size)
        bytes.copyInto(out, 0, 0, 6)
        out[6] = (newHeader.size shr 24).toByte()
        out[7] = (newHeader.size shr 16).toByte()
        out[8] = (newHeader.size shr 8).toByte()
        out[9] = newHeader.size.toByte()
        newHeader.copyInto(out, 10)
        ciphertext.copyInto(out, 10 + newHeader.size)
        return out
    }

    @Test
    fun roundTrip() {
        val vault = sampleVault()
        val bytes = VaultCodec.seal(vault)
        assertEquals("TMXV", String(bytes, 0, 4, Charsets.US_ASCII))
        assertEquals(0, bytes[4].toInt())
        assertEquals(1, bytes[5].toInt())
        val opened = VaultCodec.open(bytes, pw())
        assertEquals(vault.content, opened.content)
        assertEquals(vault.vaultId, opened.vaultId)
        assertEquals(3, opened.content.records.size)
        opened.close()
        vault.close()
    }

    @Test
    fun plaintextAndPasswordAreNotInTheFile() {
        val bytes = VaultCodec.seal(sampleVault())
        val text = String(bytes, Charsets.ISO_8859_1)
        assertFalse(text.contains("s3cret"))
        assertFalse(text.contains("192.0.2.1"))
        assertFalse(text.contains(password))
    }

    @Test
    fun wrongPasswordFailsWithoutLeakingIt() {
        val bytes = VaultCodec.seal(sampleVault())
        val wrong = "not the password"
        val e = assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(bytes, pw(wrong)) }
        assertFalse(e.message.orEmpty().contains(wrong))
        assertFalse(e.message.orEmpty().contains(password))
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(bytes, CharArray(0)) }
    }

    @Test
    fun passwordArrayIsNotModifiedByTheCodec() {
        val p = pw()
        val v = VaultCodec.create(p, fast)
        assertContentEquals(pw(), p)
        VaultCodec.open(VaultCodec.seal(v), p).close()
        assertContentEquals(pw(), p)
    }

    @Test
    fun unicodePasswordsWork() {
        val p = "pässwörd-日本語-🔑"
        val v = VaultCodec.create(pw(p), fast)
        VaultCodec.open(VaultCodec.seal(v), pw(p)).close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(VaultCodec.seal(v), pw("p")) }
    }

    @Test
    fun everySampledBitFlipInHeaderAndCiphertextFailsAuthentication() {
        val key = deviceKey()
        val vault = VaultCodec.addDeviceSlot(sampleVault(), "dev1", key)
        val bytes = VaultCodec.seal(vault)
        // Sanity: unmodified file opens through the device slot.
        VaultCodec.openWithDeviceKey(bytes, "dev1", key).close()

        val headerEnd = 10 + headerLength(bytes)
        val rnd = Random(12345)
        val positions = buildList {
            repeat(100) { add(rnd.nextInt(10, headerEnd)) } // header
            repeat(100) { add(rnd.nextInt(headerEnd, bytes.size)) } // ciphertext + tag
            addAll(listOf(10, headerEnd - 1, headerEnd, bytes.size - 1)) // boundaries
            addAll(0 until 10) // magic, version, header length
        }
        for (pos in positions) {
            val flipped = bytes.copyOf()
            flipped[pos] = (flipped[pos].toInt() xor (1 shl rnd.nextInt(8))).toByte()
            assertFailsWith<VaultException>("flip at byte $pos was accepted") {
                VaultCodec.openWithDeviceKey(flipped, "dev1", key)
            }
        }
        // A smaller sample through the password path (slow KDF).
        repeat(15) {
            val pos = rnd.nextInt(10, bytes.size)
            val flipped = bytes.copyOf()
            flipped[pos] = (flipped[pos].toInt() xor (1 shl rnd.nextInt(8))).toByte()
            assertFailsWith<VaultException>("flip at byte $pos was accepted") { VaultCodec.open(flipped, pw()) }
        }
    }

    @Test
    fun headerAndCiphertextCannotBeSwappedBetweenVaults() {
        val v1 = sampleVault()
        val v2 = sampleVault() // same password, different data key and vault id
        val f1 = VaultCodec.seal(v1)
        val f2 = VaultCodec.seal(v2)
        val h1 = 10 + headerLength(f1)
        val h2 = 10 + headerLength(f2)
        val header2Cipher1 = f2.copyOfRange(0, h2) + f1.copyOfRange(h1, f1.size)
        val header1Cipher2 = f1.copyOfRange(0, h1) + f2.copyOfRange(h2, f2.size)
        assertFailsWith<VaultException>("swap accepted") { VaultCodec.open(header2Cipher1, pw()) }
        assertFailsWith<VaultException>("swap accepted") { VaultCodec.open(header1Cipher2, pw()) }

        // Two seals of the same vault: header (with its nonce) and ciphertext are bound together too.
        val s1 = VaultCodec.seal(v1)
        val s2 = VaultCodec.seal(v1)
        val mixed = s2.copyOfRange(0, 10 + headerLength(s2)) + s1.copyOfRange(10 + headerLength(s1), s1.size)
        assertFailsWith<VaultException>("nonce/ciphertext mix accepted") { VaultCodec.open(mixed, pw()) }
    }

    @Test
    fun everySealUsesAFreshNonce() {
        val vault = sampleVault()
        val a = VaultCodec.seal(vault)
        val b = VaultCodec.seal(vault)
        assertFalse(a.contentEquals(b))
        fun nonce(bytes: ByteArray) =
            Json.parseToJsonElement(headerText(bytes)).jsonObject["contentNonce"]!!.jsonPrimitive.content
        assertNotEquals(nonce(a), nonce(b))
        // Wrapped key material is unchanged by sealing (only the content nonce changes).
        assertEquals(VaultCodec.open(a, pw()).content, VaultCodec.open(b, pw()).content)
    }

    @Test
    fun changePasswordKeepsDataKeyAndInvalidatesOldPassword() {
        val key = deviceKey()
        val original = VaultCodec.addDeviceSlot(sampleVault(), "dev1", key)
        val changed = VaultCodec.changePassword(original, pw("new password"))
        assertContentEquals(original.dataKey(), changed.dataKey())
        assertEquals(original.slotIds, changed.slotIds)

        val bytes = VaultCodec.seal(changed)
        VaultCodec.open(bytes, pw("new password")).close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(bytes, pw()) }
        // The device slot is untouched and still wraps the same data key.
        assertEquals(changed.content, VaultCodec.openWithDeviceKey(bytes, "dev1", key).content)
    }

    @Test
    fun deviceSlotOpensAndRemovalBlocksIt() {
        val key = deviceKey()
        val vault = VaultCodec.addDeviceSlot(sampleVault(), "dev1", key)
        val bytes = VaultCodec.seal(vault)
        assertEquals(vault.content, VaultCodec.openWithDeviceKey(bytes, "dev1", key).content)
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.openWithDeviceKey(bytes, "dev1", deviceKey()) }
        assertFailsWith<VaultException.NoSuchSlot> { VaultCodec.openWithDeviceKey(bytes, "nope", key) }
        assertFailsWith<VaultException.NoSuchSlot> { VaultCodec.openWithDeviceKey(bytes, VaultCodec.PASSWORD_SLOT_ID, key) }

        val removed = VaultCodec.removeSlot(vault, "dev1")
        val after = VaultCodec.seal(removed)
        assertFailsWith<VaultException.NoSuchSlot> { VaultCodec.openWithDeviceKey(after, "dev1", key) }
        VaultCodec.open(after, pw()).close()
        assertFailsWith<IllegalArgumentException> { VaultCodec.removeSlot(vault, VaultCodec.PASSWORD_SLOT_ID) }
        assertFailsWith<VaultException.NoSuchSlot> { VaultCodec.removeSlot(vault, "missing") }
        assertFailsWith<IllegalArgumentException> { VaultCodec.addDeviceSlot(vault, "dev1", ByteArray(5)) }
    }

    @Test
    fun openWithDataKeyReadsAFileWithDifferentSlots() {
        val v = sampleVault()
        val bytes = VaultCodec.seal(VaultCodec.changePassword(v, pw("other")))
        val reopened = VaultCodec.openWithDataKey(bytes, v)
        assertEquals(v.content, reopened.content)
        val foreign = sampleVault()
        assertFailsWith<VaultException.DifferentVault> { VaultCodec.openWithDataKey(bytes, foreign) }
    }

    @Test
    fun kdfParameterBoundsAreEnforcedOnCreate() {
        assertFailsWith<VaultException.KdfParamsOutOfRange> { VaultCodec.create(pw(), KdfParams(1024, 1, 1)) }
        assertFailsWith<VaultException.KdfParamsOutOfRange> { VaultCodec.create(pw(), KdfParams(8192, 0, 1)) }
        assertFailsWith<VaultException.KdfParamsOutOfRange> { VaultCodec.create(pw(), KdfParams(8192, 11, 1)) }
        assertFailsWith<VaultException.KdfParamsOutOfRange> { VaultCodec.create(pw(), KdfParams(8192, 1, 17)) }
        assertFailsWith<VaultException.KdfParamsOutOfRange> { VaultCodec.create(pw(), KdfParams(8192, 1, 0)) }
        assertFailsWith<VaultException.KdfParamsOutOfRange> {
            VaultCodec.create(pw(), KdfParams(1024 * 1024 + 1, 1, 1))
        }
    }

    @Test
    fun kdfParameterBoundsAreEnforcedOnOpenBeforeAnyWorkIsDone() {
        val bytes = VaultCodec.seal(sampleVault())
        val header = headerText(bytes)
        assertTrue(header.contains("\"memoryKiB\":8192"), header)
        val hostile = listOf(
            "\"memoryKiB\":8192" to "\"memoryKiB\":2147483647",
            "\"memoryKiB\":8192" to "\"memoryKiB\":4194304",
            "\"memoryKiB\":8192" to "\"memoryKiB\":1024",
            "\"memoryKiB\":8192" to "\"memoryKiB\":-1",
            "\"iterations\":1" to "\"iterations\":11",
            "\"iterations\":1" to "\"iterations\":2147483647",
            "\"parallelism\":1" to "\"parallelism\":17",
            "\"parallelism\":1" to "\"parallelism\":0",
        )
        for ((from, to) in hostile) {
            val modified = withHeader(bytes) { it.replace(from, to) }
            assertFailsWith<VaultException.KdfParamsOutOfRange>("$to accepted") { VaultCodec.open(modified, pw()) }
        }
    }

    @Test
    fun unknownFieldsAndRecordTypesRoundTripThroughTheFile() {
        val json = """
            {"schemaVersion":1,"vaultId":"unused","revision":4,"records":[
              {"id":"1","type":"Host","revision":1,"deviceId":"A","updatedAtEpochMs":1,"deleted":false,
               "payload":{"label":"L","address":"h","username":"u","newerField":[1,{"a":null}]},"newerRecordField":true},
              {"id":"2","type":"FutureThing","revision":1,"deviceId":"A","updatedAtEpochMs":1,"deleted":false,
               "payload":{"x":"y"}}],"history":[]}
        """.trimIndent()
        val created = VaultCodec.create(pw(), fast)
        val content = VaultJson.decodeContent(json).copy(vaultId = created.vaultId)
        val vault = created.withContent(content)
        val opened = VaultCodec.open(VaultCodec.seal(vault), pw())
        assertEquals(content, opened.content)
        assertEquals("FutureThing", opened.content.records[1].wireTypeName)
        assertEquals(
            Json.parseToJsonElement(VaultJson.encodeContent(content)),
            Json.parseToJsonElement(VaultJson.encodeContent(opened.content)),
        )
    }

    @Test
    fun cannotSealContentFromANewerSchema() {
        val vault = sampleVault()
        val newer = vault.withContent(vault.content.copy(schemaVersion = SUPPORTED_SCHEMA_VERSION + 1))
        assertFailsWith<VaultException.UnsupportedVersion> { VaultCodec.seal(newer) }
    }

    @Test
    fun newerFormatVersionIsRejected() {
        val bytes = VaultCodec.seal(sampleVault()).also { it[5] = 2 }
        assertFailsWith<VaultException.UnsupportedVersion> { VaultCodec.open(bytes, pw()) }
    }

    @Test
    fun truncatedGarbageAndOversizedInputsFailCleanly() {
        val good = VaultCodec.seal(sampleVault())
        val key = deviceKey()
        assertFailsWith<VaultException> { VaultCodec.open(ByteArray(0), pw()) }
        assertFailsWith<VaultException> { VaultCodec.open(ByteArray(3), pw()) }
        assertFailsWith<VaultException> { VaultCodec.open("TMXV".toByteArray(), pw()) }
        assertFailsWith<VaultException> { VaultCodec.open(Random(1).nextBytes(5000), pw()) }
        assertFailsWith<VaultException> { VaultCodec.openWithDeviceKey(Random(2).nextBytes(5000), "x", key) }

        // Every truncation length (coarse steps plus the last 40 bytes) is rejected.
        val lengths = (0 until good.size step 37).toList() + (good.size - 40 until good.size).toList()
        for (len in lengths) {
            assertFailsWith<VaultException>("truncated to $len accepted") { VaultCodec.open(good.copyOf(len), pw()) }
        }
        // Appended trailing bytes break the authentication tag.
        assertFailsWith<VaultException> { VaultCodec.open(good + byteArrayOf(0), pw()) }

        // Oversized file and absurd header lengths.
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.open(ByteArray(VaultCodec.MAX_FILE_BYTES + 1), pw()) }
        val hugeHeader = good.copyOf().also { for (i in 6..9) it[i] = 0xff.toByte() }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.open(hugeHeader, pw()) }
        val bigButLegal = good.copyOf().also {
            it[6] = 0; it[7] = 1; it[8] = 0; it[9] = 1 // 65537 > 64 KiB
        }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.open(bigButLegal, pw()) }
        val zeroHeader = good.copyOf().also { for (i in 6..9) it[i] = 0 }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.open(zeroHeader, pw()) }
    }

    @Test
    fun malformedHeadersFailCleanly() {
        val bytes = VaultCodec.seal(sampleVault())
        val broken = listOf<(String) -> String>(
            { "not json at all" },
            { "{}" },
            { it.replace("argon2id", "scrypt") },
            { it.replace("\"type\":\"password\"", "\"type\":\"mystery\"") },
            { it.replace("\"slots\":[", "\"slots\":[],\"extra\":[") },
            { it.replace(Regex("\"salt\":\"[^\"]*\""), "\"salt\":\"AAAA\"") },
            { it.replace(Regex("\"nonce\":\"[^\"]*\""), "\"nonce\":\"!!!!\"") },
        )
        for (transform in broken) {
            assertFailsWith<VaultException> { VaultCodec.open(withHeader(bytes, transform), pw()) }
        }
    }

    @Test
    fun openVaultCannotBeUsedAfterClose() {
        val vault = sampleVault()
        vault.close()
        assertFailsWith<IllegalStateException> { VaultCodec.seal(vault) }
    }

    @Test
    fun defaultKdfParametersCompleteAndRoundTrip() {
        val vault = VaultCodec.create(pw()) // 64 MiB, t=3, p=4
        val bytes = VaultCodec.seal(vault)
        assertTrue(headerText(bytes).contains("\"memoryKiB\":65536"))
        val opened = VaultCodec.open(bytes, pw())
        assertEquals(vault.content, opened.content)
    }
}
