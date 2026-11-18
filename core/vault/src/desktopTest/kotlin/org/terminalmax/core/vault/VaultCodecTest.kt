// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import java.util.concurrent.atomic.AtomicInteger
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class VaultCodecTest {
    /** Smallest accepted cost, so the suite stays fast. */
    private val fast = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)
    private val password = "correct horse battery staple"

    @AfterTest
    fun resetHooks() {
        VaultCrypto.kdfObserver = null
    }

    private fun pw(value: String = password) = value.toCharArray()

    private fun sampleVault(): OpenVault {
        val created = VaultCodec.create(pw(), fast)
        val editor = VaultEditor(created.content, "dev-A")
        editor.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin"), id = "h1")
        editor.upsertIdentity(IdentityPayload("root", "root", password = "s3cret"), id = "i1")
        editor.upsertSnippet(SnippetPayload("s", "uptime"), id = "s1")
        return created.withContent(editor.content).also { created.close() }
    }

    private fun passwordSlotId(v: OpenVault) = v.slots.first { it.type == SlotTypes.PASSWORD }.id

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

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun toHex(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private val passwordSlotJson = Regex("\\{\"id\":\"pw-[0-9a-f]{16}\",\"type\":\"password\"[^{}]*\\}")

    /** Adds [extra] copies of the first password slot (distinct ids) to the header text. */
    private fun addPasswordSlots(header: String, extra: Int): String {
        val slot = passwordSlotJson.find(header)!!.value
        val copies = (1..extra).joinToString("") { n ->
            "," + slot.replace(Regex("\"id\":\"pw-[0-9a-f]{16}\""), "\"id\":\"pw-" + n.toString().padStart(16, '0') + "\"")
        }
        return header.replace(slot, slot + copies)
    }

    // ------------------------------------------------------------------ primitives (known answers)

    @Test
    fun hkdfMatchesRfc5869TestCase1() {
        val okm = VaultCrypto.hkdf(
            ikm = ByteArray(22) { 0x0b },
            salt = ByteArray(13) { it.toByte() },
            info = ByteArray(10) { (0xf0 + it).toByte() },
            length = 42,
        )
        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            toHex(okm),
        )
    }

    // ------------------------------------------------------------------ format basics

    @Test
    fun roundTrip() {
        val vault = sampleVault()
        val bytes = VaultCodec.seal(vault)
        assertEquals("TMXV", String(bytes, 0, 4, Charsets.US_ASCII))
        assertEquals(0, bytes[4].toInt())
        assertEquals(2, bytes[5].toInt())
        val opened = VaultCodec.open(bytes, pw())
        assertEquals(vault.content, opened.content)
        assertEquals(vault.vaultId, opened.vaultId)
        assertEquals(1L, opened.keyEpoch)
        assertEquals(1L, opened.headerRevision)
        assertEquals(3, opened.content.records.size)
        opened.close()
        vault.close()
    }

    @Test
    fun inspectReadsTheHeaderWithoutKeys() {
        val bytes = VaultCodec.seal(sampleVault())
        val info = VaultCodec.inspect(bytes)
        assertEquals(1L, info.keyEpoch)
        assertEquals(1L, info.headerRevision)
        assertEquals(listOf(SlotTypes.PASSWORD), info.slots.map { it.type })
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
    fun slotIdsAreOpaqueRandomIds() {
        val v = VaultCodec.addPasswordSlot(sampleVault(), pw("second"), fast)
        assertTrue(v.slotIds.all { Regex("pw-[0-9a-f]{16}").matches(it) }, v.slotIds.toString())
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

    // ------------------------------------------------------------------ password encoding

    @Test
    fun composedAndDecomposedPasswordsOpenTheSameVault() {
        val composed = "caf\u00e9-\u00c5ngstr\u00f6m"
        val decomposed = "cafe\u0301-A\u030angstro\u0308m"
        assertNotEquals(composed, decomposed)
        val v = VaultCodec.create(pw(composed), fast)
        val bytes = VaultCodec.seal(v)
        VaultCodec.open(bytes, pw(composed)).close()
        VaultCodec.open(bytes, pw(decomposed)).close()
        // The ANGSTROM SIGN normalises to the letter with ring above.
        val other = VaultCodec.seal(VaultCodec.create(pw("\u212B"), fast))
        VaultCodec.open(other, pw("\u00c5")).close()
    }

    @Test
    fun passwordEncodingIsStrictAboutUnpairedSurrogates() {
        assertFailsWith<IllegalArgumentException> { VaultCrypto.encodePassword("ab\ud800cd".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { VaultCrypto.encodePassword("\udc00".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { VaultCodec.create("x\ud800".toCharArray(), fast) }
        // A valid surrogate pair is fine, and two lone surrogates never collapse to the same bytes.
        assertContentEquals(
            "\ud83d\udd11".toByteArray(Charsets.UTF_8),
            VaultCrypto.encodePassword("\ud83d\udd11".toCharArray()),
        )
    }

    @Test
    fun passwordEncodingDoesNotTouchTheCallersArray() {
        val chars = "e\u0301x".toCharArray()
        val copy = chars.copyOf()
        VaultCrypto.encodePassword(chars)
        assertContentEquals(copy, chars)
    }

    // ------------------------------------------------------------------ integrity

    @Test
    fun everySampledBitFlipInHeaderAndCiphertextFailsAuthentication() {
        val vault = sampleVault()
        val bytes = VaultCodec.seal(vault)
        val secret = vault.exportLocalUnlockSecret()
        // Sanity: the unmodified file opens through the (cheap) local unlock path.
        VaultCodec.openWithLocalUnlockSecret(bytes, secret).close()

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
                VaultCodec.openWithLocalUnlockSecret(flipped, secret)
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
    fun tamperedCiphertextWithTheRightPasswordIsAnIntegrityFailure() {
        val bytes = VaultCodec.seal(sampleVault())
        val flipped = bytes.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFailsWith<VaultException.IntegrityFailure> { VaultCodec.open(flipped, pw()) }
        // A header edit that keeps the slots intact (header revision) breaks the content tag, not the slot.
        val edited = withHeader(bytes) { it.replace("\"headerRevision\":1", "\"headerRevision\":2") }
        assertFailsWith<VaultException.IntegrityFailure> { VaultCodec.open(edited, pw()) }
        // The key epoch is bound into the slot AAD as well.
        val epoch = withHeader(bytes) { it.replace("\"keyEpoch\":1", "\"keyEpoch\":2") }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(epoch, pw()) }
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

        // Two seals of the same vault: header (with its write salt) and ciphertext are bound together too.
        val s1 = VaultCodec.seal(v1)
        val s2 = VaultCodec.seal(v1)
        val mixed = s2.copyOfRange(0, 10 + headerLength(s2)) + s1.copyOfRange(10 + headerLength(s1), s1.size)
        assertFailsWith<VaultException>("salt/ciphertext mix accepted") { VaultCodec.open(mixed, pw()) }
    }

    @Test
    fun everySealUsesAFreshWriteSalt() {
        val vault = sampleVault()
        val a = VaultCodec.seal(vault)
        val b = VaultCodec.seal(vault)
        assertFalse(a.contentEquals(b))
        fun salt(bytes: ByteArray) =
            Json.parseToJsonElement(headerText(bytes)).jsonObject["writeSalt"]!!.jsonPrimitive.content
        assertNotEquals(salt(a), salt(b))
        // Wrapped key material is unchanged by sealing (only the write salt changes).
        assertEquals(VaultCodec.open(a, pw()).content, VaultCodec.open(b, pw()).content)
    }

    // ------------------------------------------------------------------ key rotation

    @Test
    fun changePasswordRotatesTheDataKeySoOldCopiesCannotOpenOrForgeNewFiles() {
        val original = sampleVault()
        val oldFile = VaultCodec.seal(original)
        val changed = VaultCodec.changePassword(original, pw("new password"))
        assertEquals(original.keyEpoch + 1, changed.keyEpoch)
        assertEquals(original.headerRevision + 1, changed.headerRevision)
        assertFalse(original.dataKey().contentEquals(changed.dataKey()), "data key must change")
        assertEquals(original.slotIds, changed.slotIds)

        val newFile = VaultCodec.seal(changed)
        VaultCodec.open(newFile, pw("new password")).close()
        // The old password cannot open the new file ...
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(newFile, pw()) }
        // ... the old data key is refused by epoch ...
        val mismatch = assertFailsWith<VaultException.KeyEpochMismatch> { VaultCodec.openWithDataKey(newFile, original) }
        assertEquals(2L, mismatch.found)
        assertEquals(1L, mismatch.expected)
        // ... and cannot decrypt even when pretending to be at the new epoch.
        val oldKeyNewEpoch = OpenVault(changed.content, changed.header, original.dataKey().copyOf())
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.openWithDataKey(newFile, oldKeyNewEpoch) }
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(newFile, original))
        // The old file still opens with the old password (history cannot be rewritten) but is older by epoch.
        assertEquals(1L, VaultCodec.open(oldFile, pw()).keyEpoch)
        assertEquals(1L, VaultCodec.inspect(oldFile).keyEpoch)
    }

    @Test
    fun aReplayedOldFileIsRefusedByEpochWhenOpenedWithTheCurrentDataKey() {
        val v1 = sampleVault()
        val oldFile = VaultCodec.seal(v1)
        val v2 = VaultCodec.changePassword(v1, pw("new password"))
        val e = assertFailsWith<VaultException.KeyEpochMismatch> { VaultCodec.openWithDataKey(oldFile, v2) }
        assertEquals(1L, e.found)
        assertEquals(2L, e.expected)
    }

    // ------------------------------------------------------------------ KDF limits

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
        // In bounds for the format but beyond what a phone should do, or beyond the per-file budget.
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.create(pw(), KdfParams(512 * 1024, 1, 1)) }
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.create(pw(), KdfParams(200 * 1024, 10, 1)) }
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
        val derivations = AtomicInteger()
        VaultCrypto.kdfObserver = { derivations.incrementAndGet() }
        for ((from, to) in hostile) {
            val modified = withHeader(bytes) { it.replace(from, to) }
            assertFailsWith<VaultException.KdfParamsOutOfRange>("$to accepted") { VaultCodec.open(modified, pw()) }
        }
        assertEquals(0, derivations.get(), "a key derivation ran for a rejected header")
    }

    @Test
    fun tooManyPasswordSlotsAreRejectedBeforeAnyKeyDerivation() {
        val bytes = VaultCodec.seal(sampleVault())
        val derivations = AtomicInteger()
        VaultCrypto.kdfObserver = { derivations.incrementAndGet() }
        // 1 genuine + 15 attacker slots at the maximum the format allows.
        val hostile = withHeader(bytes) { header ->
            addPasswordSlots(header, 15).replace("\"memoryKiB\":8192", "\"memoryKiB\":1048576")
                .replace("\"iterations\":1", "\"iterations\":10")
        }
        val started = System.nanoTime()
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.open(hostile, pw()) }
        assertTrue(System.nanoTime() - started < 2_000_000_000L, "rejection must be immediate")
        // Also just one slot too many with otherwise harmless parameters.
        val three = withHeader(bytes) { addPasswordSlots(it, 2) }
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.open(three, pw()) }
        assertEquals(0, derivations.get(), "a key derivation ran for a rejected header")
        // Two slots are within the limit.
        val two = withHeader(bytes) { addPasswordSlots(it, 1) }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(two, pw("wrong")) }
        assertEquals(2, derivations.get())
    }

    @Test
    fun theMemoryCeilingAndTheTotalCostBudgetAreCheckedBeforeDerivation() {
        val bytes = VaultCodec.seal(sampleVault())
        val derivations = AtomicInteger()
        VaultCrypto.kdfObserver = { derivations.incrementAndGet() }
        val aboveCeiling = withHeader(bytes) { it.replace("\"memoryKiB\":8192", "\"memoryKiB\":${128 * 1024 + 1}") }
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.open(aboveCeiling, pw()) }
        // A lower ceiling chosen by the caller (a small device) applies as well.
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.open(bytes, pw(), memoryCeilingKiB = 8 * 1024 - 1) }
        // Two slots of 64 MiB at 10 passes: each within the ceiling, together over the budget.
        val overBudget = withHeader(bytes) {
            addPasswordSlots(it, 1).replace("\"memoryKiB\":8192", "\"memoryKiB\":65536")
                .replace("\"iterations\":1", "\"iterations\":10")
        }
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.open(overBudget, pw()) }
        assertEquals(0, derivations.get())
    }

    @Test
    fun theRememberedPasswordSlotIsTriedFirst() {
        var vault = sampleVault()
        vault = VaultCodec.addPasswordSlot(vault, pw("second"), fast)
        val second = vault.slots.last { it.type == SlotTypes.PASSWORD }.id
        val bytes = VaultCodec.seal(vault)
        val derivations = AtomicInteger()
        VaultCrypto.kdfObserver = { derivations.incrementAndGet() }
        VaultCodec.open(bytes, pw("second")).close()
        assertEquals(2, derivations.get(), "without a hint the slots are tried in file order")
        derivations.set(0)
        VaultCodec.open(bytes, pw("second"), preferredSlotId = second).close()
        assertEquals(1, derivations.get(), "the preferred slot must be tried first")
        assertFailsWith<IllegalArgumentException> {
            VaultCodec.addPasswordSlot(vault, pw("third"), fast) // a third password slot is refused
        }
    }

    // ------------------------------------------------------------------ content validation

    private fun authenticBut(content: VaultContent): ByteArray {
        val vault = VaultCodec.create(pw(), fast)
        val file = VaultCodec.sealWithoutContentValidation(vault.withContent(content.copy(vaultId = vault.vaultId)))
        return file
    }

    private fun rec(id: String, revision: Long = 1, type: RecordType = RecordType.Snippet, device: String = "A") =
        VaultRecord(id, type, revision, device, 0, false, JsonObject(mapOf("v" to JsonPrimitive("x"))))

    private fun base(vararg records: VaultRecord, revision: Long = 1, history: List<VaultRecord> = emptyList()) =
        VaultContent(SUPPORTED_SCHEMA_VERSION, "v", revision, records.toList(), history)

    @Test
    fun malformedButAuthenticContentIsRejectedOnOpenAndOnSeal() {
        val bad = mapOf(
            "negative content revision" to base(revision = -1),
            "content revision above 2^53" to base(revision = MAX_REVISION + 1),
            "Long.MAX_VALUE content revision" to base(revision = Long.MAX_VALUE),
            "negative record revision" to base(rec("a", -3)),
            "zero record revision" to base(rec("a", 0)),
            "Long.MAX_VALUE record revision" to base(rec("a", Long.MAX_VALUE)),
            "duplicate ids" to base(rec("a", 1), rec("a", 2)),
            "same id with two types" to base(rec("a", 1), rec("a", 2, RecordType.Host)),
            "empty id" to base(rec("")),
            "over-long id" to base(rec("x".repeat(129))),
            "empty device id" to base(rec("a", device = "")),
            "history of 201" to base(history = (1..201).map { rec("h$it", it.toLong()) }),
            "history id with another type" to base(rec("a", 2, RecordType.Host), history = listOf(rec("a", 1))),
            "oversized payload" to base(
                VaultRecord("a", RecordType.Snippet, 1, "A", 0, false, JsonObject(mapOf("v" to JsonPrimitive("x".repeat(300_000))))),
            ),
            "too many records" to base(*(0..VaultContent.MAX_RECORDS).map { rec("r$it") }.toTypedArray()),
        )
        for ((name, content) in bad) {
            val file = authenticBut(content)
            assertFailsWith<VaultException.InvalidContent>("opened: $name") { VaultCodec.open(file, pw()) }
            val vault = VaultCodec.create(pw(), fast)
            assertFailsWith<VaultException.InvalidContent>("sealed: $name") {
                VaultCodec.seal(vault.withContent(content.copy(vaultId = vault.vaultId)))
            }
        }
    }

    @Test
    fun sealRefusesAnOldSchemaVersion() {
        val vault = VaultCodec.create(pw(), fast)
        val old = vault.withContent(vault.content.copy(schemaVersion = 1))
        assertFailsWith<VaultException.InvalidContent> { VaultCodec.seal(old) }
    }

    @Test
    fun editorNeverOverflowsRevisions() {
        val atLimit = VaultContent(SUPPORTED_SCHEMA_VERSION, "v", MAX_REVISION, listOf(rec("a", MAX_REVISION)))
        val editor = VaultEditor(atLimit, "A")
        assertFailsWith<VaultException.InvalidContent> { editor.upsert(RecordType.Snippet, "a", JsonObject(emptyMap())) }
        assertFailsWith<VaultException.InvalidContent> { editor.delete("a") }
        assertFailsWith<VaultException.InvalidContent> { editor.upsert(RecordType.Snippet, "b", JsonObject(emptyMap())) }
        assertEquals(atLimit, editor.content)
    }

    // ------------------------------------------------------------------ framing and versions

    @Test
    fun unknownFieldsAndRecordTypesRoundTripThroughTheFile() {
        val json = """
            {"schemaVersion":2,"vaultId":"unused","revision":4,"records":[
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
    fun newerAndOlderFormatVersionsAreRejected() {
        val newer = VaultCodec.seal(sampleVault()).also { it[5] = 3 }
        assertFailsWith<VaultException.UnsupportedVersion> { VaultCodec.open(newer, pw()) }
        val v1 = VaultCodec.seal(sampleVault()).also { it[5] = 1 }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.open(v1, pw()) }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.inspect(v1) }
    }

    @Test
    fun truncatedGarbageAndOversizedInputsFailCleanly() {
        val good = VaultCodec.seal(sampleVault())
        assertFailsWith<VaultException> { VaultCodec.open(ByteArray(0), pw()) }
        assertFailsWith<VaultException> { VaultCodec.open(ByteArray(3), pw()) }
        assertFailsWith<VaultException> { VaultCodec.open("TMXV".toByteArray(), pw()) }
        assertFailsWith<VaultException> { VaultCodec.open(Random(1).nextBytes(5000), pw()) }
        assertFailsWith<VaultException> { VaultCodec.openWithLocalUnlockSecret(Random(2).nextBytes(5000), Random(3).nextBytes(80)) }

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
            { it.replace("\"keyEpoch\":1", "\"keyEpoch\":0") },
            { it.replace("\"keyEpoch\":1", "\"keyEpoch\":4294967296") },
            { it.replace("\"headerRevision\":1", "\"headerRevision\":-1") },
            { it.replace(Regex("\"writeSalt\":\"[^\"]*\""), "\"writeSalt\":\"AAAA\"") },
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
    fun sealingTooMuchDataFailsWithAVaultExceptionNotAnIllegalState() {
        val vault = VaultCodec.create(pw(), fast)
        // 40 records of ~250 KiB of incompressible-looking text exceed the 8 MiB file limit.
        val rnd = Random(7)
        val big = (0 until 40).map { i ->
            val text = buildString { repeat(240_000) { append(('a' + rnd.nextInt(26))) } }
            VaultRecord("r$i", RecordType.Snippet, 1, "A", 0, false, JsonObject(mapOf("v" to JsonPrimitive(text))))
        }
        val content = vault.content.copy(revision = 1, records = big)
        assertFailsWith<VaultException.InvalidContent> { VaultCodec.seal(vault.withContent(content)) }
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
