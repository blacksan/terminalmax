// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Format v2 final layout: golden vectors from an independent encoder, key commitment, the epoch chain, the local
 * unlock secret and the hostile cases that follow from "password slots only".
 */
class VaultFormatV2Test {
    private val fast = KdfParams(memoryKiB = 8 * 1024, iterations = 1, parallelism = 1)

    // ---- golden data: produced by a throw-away encoder that uses only javax.crypto and BouncyCastle's Argon2,
    // ---- never by this codebase. Epoch 1 key = 00..1f, epoch 2 key = 80..9f.
    private val goldenEpoch1 =
        "544d58560002000001b77b226b6466223a226172676f6e326964222c227661756c744964223a22676f6c64656e2d7661756c" +
        "74222c226b657945706f6368223a312c226865616465725265766973696f6e223a312c22736c6f7473223a5b7b226964223a" +
        "2270772d30313233343536373839616263646566222c2274797065223a2270617373776f7264222c2273616c74223a224151" +
        "4944424155474277674a4367734d4451345045413d3d222c226d656d6f72794b6942223a383139322c22697465726174696f" +
        "6e73223a312c22706172616c6c656c69736d223a312c226e6f6e6365223a2245524954464255574678675a47687363222c22" +
        "777261707065644b6579223a22302f696e57434654552b386b5630694238586d416b6a746141534f33694f37466e6c516a50" +
        "51474274483775636351532b742f56507751667657426972703956227d5d2c22777269746553616c74223a224b536f724c43" +
        "30754c7a41784d6a4d304e5459334f446b364f7a7739506a394151554a44524556475230673d222c226b6579436f6d6d6974" +
        "223a222b4656725050706277426f652f4a6d54336834703375397166755436366d6b4b2b77567834736843476e383d227d38" +
        "f3e9bcdee6a1ddd42ac6a3ae10020096f23a91b90918f5c7654750ab06975fa28910517e4fff94dbb4d4114a8915093c2975" +
        "b0be3a5d67d2841a7ae0cf54e08c26414ae344c6781ab28bf30af381b05b48de5bde10d300e44340b6c6330adfed51cf9a11" +
        "053a5983cb777fbc3b69de80bef9a74291156092cdeabd02459c0c56288fa69340b1df9a120a4807760c071900cf488f30ac" +
        "dd9c41753533f1701ad23b69fe2f5a0d5bf848260de931e496be667e079b7ab8bebf6df32e511f4c36533335711769487584" +
        "f630fe8043d764c330eadc277490eb358d041efb011fb66c10c4dc9c2b33865e57e58a4f69fd3a6d33d37280053c43"
    private val goldenEpoch2 =
        "544d58560002000001f27b226b6466223a226172676f6e326964222c227661756c744964223a22676f6c64656e2d7661756c" +
        "74222c226b657945706f6368223a322c226865616465725265766973696f6e223a322c22736c6f7473223a5b7b226964223a" +
        "2270772d30313233343536373839616263646566222c2274797065223a2270617373776f7264222c2273616c74223a224177" +
        "51464267634943516f4c4441304f4478415245673d3d222c226d656d6f72794b6942223a383139322c22697465726174696f" +
        "6e73223a312c22706172616c6c656c69736d223a312c226e6f6e6365223a22457851564668635947526f6248423065222c22" +
        "777261707065644b6579223a22536642453561353158352f6441503641337246554b515657626b755a564879373964536164" +
        "446e4642365848614d31364a57574b44567a41443861435345584b227d5d2c22777269746553616c74223a224b7977744c69" +
        "38774d54497a4e4455324e7a67354f6a73385054342f5145464351305246526b644953556f3d222c226b6579436f6d6d6974" +
        "223a2270676e42445573694c48444c71427a636f724c544f4f37486c447557505a4966345169613748784f524a673d222c22" +
        "65706f63684c696e6b223a224e7a5744356d6a58566951586d38753637625a537a4539724373315561447870563678534570" +
        "42437035493d227d51d37fdfc419ce5c2b8a942d17292c33b12a1f03162da4611ad792adbfce15830d62f0b1a15694314884" +
        "c850f0c5381e2ba1a2cd8d3e31baf92800b2cb781c90e0907b52df9a1603900d433034d27de95985f60859e3f95bb83e7eda" +
        "d62af9d199f2f7f40674fe9d775b018f0436bdaf1349dd8c8f28001d5789cbb66517abdbd1f7e79ee75691e818e30a27d5e9" +
        "070047df843c6dd9948b9214bd3dbea7200561d3e03db6b72985430afa980639065ebac99e1e7d835fab479b9706d91a3ee5" +
        "62bc6000a1d2447a802f131654222e43cbe65adbb608f4196c12f7c134613cd6639a5f001fffb544b17f3b0fe47d3d76803d" +
        "f68f95225512cbc792"

    private val goldenGcm = "376eb772ab91a763f94c292dc581ba85c94d2a6417dc232a33"

    private fun hex(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private fun toHex(b: ByteArray) = b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    private fun seq(start: Int, n: Int) = ByteArray(n) { (start + it).toByte() }

    private fun pw(v: String) = v.toCharArray()

    // ---- independent primitives (javax.crypto only)

    private fun mac(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA256").run { init(SecretKeySpec(key, "HmacSHA256")); doFinal(data) }

    private fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val prk = mac(salt, ikm)
        var t = ByteArray(0)
        var out = ByteArray(0)
        var i = 1
        while (out.size < length) {
            t = mac(prk, t + info + byteArrayOf(i.toByte()))
            out += t
            i++
        }
        return out.copyOf(length)
    }

    private fun u32(v: Long) = byteArrayOf((v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte())

    private fun gcm(key: ByteArray, nonce: ByteArray, aad: ByteArray, pt: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            updateAAD(aad)
            doFinal(pt)
        }

    private fun headerText(bytes: ByteArray): String {
        val len = ((bytes[6].toInt() and 0xff) shl 24) or ((bytes[7].toInt() and 0xff) shl 16) or
            ((bytes[8].toInt() and 0xff) shl 8) or (bytes[9].toInt() and 0xff)
        return String(bytes, 10, len, Charsets.UTF_8)
    }

    private fun withHeader(bytes: ByteArray, transform: (String) -> String): ByteArray {
        val oldLen = headerText(bytes).toByteArray(Charsets.UTF_8).size
        val newHeader = transform(headerText(bytes)).toByteArray(Charsets.UTF_8)
        val ciphertext = bytes.copyOfRange(10 + oldLen, bytes.size)
        val out = ByteArray(10 + newHeader.size + ciphertext.size)
        bytes.copyInto(out, 0, 0, 6)
        u32(newHeader.size.toLong()).copyInto(out, 6)
        newHeader.copyInto(out, 10)
        ciphertext.copyInto(out, 10 + newHeader.size)
        return out
    }

    private fun secretKeyOf(secret: ByteArray) = secret.copyOfRange(secret.size - 32, secret.size)

    private fun sample(): OpenVault {
        val created = VaultCodec.create(pw("pw"), fast)
        val editor = VaultEditor(created.content, "A")
        editor.upsertSnippet(SnippetPayload("s", "uptime"), id = "s1")
        return created.withContent(editor.content).also { created.close() }
    }

    private val goldenContent2 = VaultContent(
        schemaVersion = 2,
        vaultId = "golden-vault",
        revision = 3,
        records = listOf(
            VaultRecord(
                "s1", RecordType.Snippet, 3, "A", 0, false,
                JsonObject(mapOf("name" to JsonPrimitive("up"), "command" to JsonPrimitive("uptime -p"))),
            ),
        ),
    )

    // ------------------------------------------------------------------ golden vectors

    @Test
    fun aesGcmMatchesJavaxDirectlyAndAKnownAnswer() {
        val key = seq(0, 32)
        val nonce = seq(0, 12)
        val expected = gcm(key, nonce, "aad".toByteArray(), "plaintext".toByteArray())
        assertEquals(goldenGcm, toHex(expected))
        assertContentEquals(expected, VaultCrypto.gcmEncrypt(key, nonce, "aad".toByteArray(), "plaintext".toByteArray()))
        assertContentEquals("plaintext".toByteArray(), VaultCrypto.gcmDecrypt(key, nonce, "aad".toByteArray(), expected))
    }

    @Test
    fun hkdfAndHmacMatchAnIndependentImplementationOnRandomInputs() {
        val rnd = Random(99)
        repeat(50) {
            val ikm = rnd.nextBytes(rnd.nextInt(1, 64))
            val salt = rnd.nextBytes(rnd.nextInt(1, 40))
            val info = rnd.nextBytes(rnd.nextInt(0, 50))
            assertContentEquals(hkdf(ikm, salt, info, 32), VaultCrypto.hkdf(ikm, salt, info, 32))
            assertContentEquals(mac(ikm, info), VaultCrypto.hmacSha256(ikm, info))
        }
    }

    @Test
    fun goldenFilesWrittenByAnIndependentEncoderOpenWithThePasswordAndTheLocalSecret() {
        val e1 = hex(goldenEpoch1)
        val e2 = hex(goldenEpoch2)
        val opened1 = VaultCodec.open(e1, pw("golden pw one"))
        assertEquals(1L, opened1.keyEpoch)
        assertEquals("up", (opened1.content.records.single().payload["name"] as JsonPrimitive).content)

        val opened2 = VaultCodec.open(e2, pw("golden pw two"))
        assertEquals(2L, opened2.keyEpoch)
        assertEquals(2L, opened2.headerRevision)
        assertEquals(goldenContent2, opened2.content)
        assertContentEquals(seq(0x80, 32), secretKeyOf(opened2.exportLocalUnlockSecret()))

        // The (cheap) key-only path agrees, and a secret from the other epoch is refused by epoch.
        val secret2 = VaultCodec.encodeLocalUnlockSecret("golden-vault", 2L, seq(0x80, 32))
        assertEquals(goldenContent2, VaultCodec.openWithLocalUnlockSecret(e2, secret2).content)
        val secret1 = VaultCodec.encodeLocalUnlockSecret("golden-vault", 1L, seq(0, 32))
        val mismatch = assertFailsWith<VaultException.KeyEpochMismatch> { VaultCodec.openWithLocalUnlockSecret(e2, secret1) }
        assertEquals(2L, mismatch.found)
        assertEquals(1L, mismatch.expected)
    }

    @Test
    fun theGoldenEpochLinkVerifiesFromTheEpoch1KeyAndNothingElse() {
        val e1 = VaultCodec.open(hex(goldenEpoch1), pw("golden pw one"))
        val e2 = hex(goldenEpoch2)
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(e2, e1))
        // The same file seen from a vault that holds some other epoch-1 key is unverified.
        val other = VaultCodec.create(pw("x"), fast, vaultId = "golden-vault")
        assertEquals(EpochLinkStatus.Unverified, VaultCodec.verifyEpochLink(e2, other))
        // A flipped bit in the link or in the key commitment breaks the chain (and the commitment check on open).
        for (field in listOf("epochLink", "keyCommit")) {
            val tampered = withHeader(e2) { h ->
                val m = Regex("\"$field\":\"([A-Za-z0-9+/=]+)\"").find(h)!!
                val old = m.groupValues[1]
                val flipped = (if (old[0] == 'A') 'B' else 'A') + old.substring(1)
                h.replace(old, flipped)
            }
            if (field == "epochLink") assertEquals(EpochLinkStatus.Unverified, VaultCodec.verifyEpochLink(tampered, e1))
            assertFailsWith<VaultException> { VaultCodec.open(tampered, pw("golden pw two")) }
        }
    }

    // ------------------------------------------------------------------ key commitment

    @Test
    fun theHeaderCommitsToTheDataKeyWithTheDocumentedConstruction() {
        val vault = sample()
        val bytes = VaultCodec.seal(vault)
        val key = secretKeyOf(vault.exportLocalUnlockSecret())
        val expected = hkdf(key, vault.vaultId.toByteArray(), "TMXV2 key commitment".toByteArray() + u32(1), 32)
        val header = headerText(bytes)
        val committed = Regex("\"keyCommit\":\"([A-Za-z0-9+/=]+)\"").find(header)!!.groupValues[1]
        assertEquals(java.util.Base64.getEncoder().encodeToString(expected), committed)
        assertFalse(header.contains("epochLink"), "epoch 1 has no link")
    }

    @Test
    fun aWrongCommitmentIsRejectedEvenWhenTheSlotUnwraps() {
        val bytes = VaultCodec.seal(sample())
        val tampered = withHeader(bytes) { h ->
            val old = Regex("\"keyCommit\":\"([A-Za-z0-9+/=]+)\"").find(h)!!.groupValues[1]
            h.replace(old, java.util.Base64.getEncoder().encodeToString(ByteArray(32)))
        }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(tampered, pw("pw")) }
    }

    // ------------------------------------------------------------------ epoch chain

    @Test
    fun aRotationIsLinkedToThePreviousEpochOneStepAtATime() {
        val v1 = sample()
        val v2 = VaultCodec.changePassword(v1, pw("two"))
        val v3 = VaultCodec.changePassword(v2, pw("three"))
        val f2 = VaultCodec.seal(v2)
        val f3 = VaultCodec.seal(v3)
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(f2, v1))
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(f3, v2))
        // Two epochs ahead cannot be verified from the old key alone.
        assertEquals(EpochLinkStatus.Unverified, VaultCodec.verifyEpochLink(f3, v1))
        // Not newer: nothing to verify.
        assertEquals(EpochLinkStatus.NotApplicable, VaultCodec.verifyEpochLink(f2, v2))
        assertEquals(EpochLinkStatus.NotApplicable, VaultCodec.verifyEpochLink(f2, v3))
    }

    @Test
    fun aStrangerWhoKnowsNoKeyCannotMintANextEpochThatVerifiesOrOpens() {
        val honest = sample()
        // The attacker builds a vault of the same id with its own password and key and rotates it to epoch 2.
        val attackerRoot = VaultCodec.create(pw("evil"), fast, vaultId = honest.vaultId)
        val attacker = VaultCodec.changePassword(attackerRoot, pw("evil2"))
        val minted = VaultCodec.seal(attacker.withContent(honest.content.copy(revision = honest.content.revision + 1)))
        assertEquals(2L, VaultCodec.inspect(minted).keyEpoch)
        assertEquals(EpochLinkStatus.Unverified, VaultCodec.verifyEpochLink(minted, honest))
        assertFailsWith<VaultException.KeyEpochMismatch> { VaultCodec.openWithDataKey(minted, honest) }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(minted, pw("pw")) }
        // There is no slot type that a public header could be extended with.
        val withDeviceSlot = withHeader(VaultCodec.seal(honest)) { it.replace("\"type\":\"password\"", "\"type\":\"device-x25519\"") }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(withDeviceSlot, pw("pw")) }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.inspect(withDeviceSlot) }
    }

    @Test
    fun anEpochOneFileMayNotCarryALinkAndLaterEpochsMust() {
        val v1 = sample()
        val v2 = VaultCodec.changePassword(v1, pw("two"))
        val f2 = VaultCodec.seal(v2)
        val noLink = withHeader(f2) { h -> h.replace(Regex(",\"epochLink\":\"[^\"]*\""), "") }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(noLink, pw("two")) }
        val f1 = VaultCodec.seal(v1)
        val link = Regex("\"epochLink\":\"([^\"]*)\"").find(headerText(f2))!!.groupValues[1]
        val extraLink = withHeader(f1) { h -> h.dropLast(1) + ",\"epochLink\":\"$link\"}" }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(extraLink, pw("pw")) }
    }

    @Test
    fun theNewEpochSlotAndLinkAreCoveredByTheContentTag() {
        val v1 = sample()
        val f2 = VaultCodec.seal(VaultCodec.changePassword(v1, pw("two")))
        // Swapping in another (genuine, same-vault) link breaks the content AAD even though the slot still opens.
        val other = VaultCodec.seal(VaultCodec.changePassword(v1, pw("two")))
        val otherLink = Regex("\"epochLink\":\"([^\"]*)\"").find(headerText(other))!!.groupValues[1]
        val swapped = withHeader(f2) { h -> h.replace(Regex("\"epochLink\":\"[^\"]*\""), "\"epochLink\":\"$otherLink\"") }
        assertFailsWith<VaultException> { VaultCodec.open(swapped, pw("two")) }
    }

    // ------------------------------------------------------------------ local unlock secret

    @Test
    fun theLocalUnlockSecretOpensTheSameEpochAndFailsAfterAnyRekey() {
        val vault = sample()
        val file = VaultCodec.seal(vault)
        val secret = vault.exportLocalUnlockSecret()
        assertEquals(vault.content, VaultCodec.openWithLocalUnlockSecret(file, secret).content)
        assertEquals("TMXK", String(secret, 0, 4, Charsets.US_ASCII))
        assertEquals(1, secret[4].toInt())

        val rekeyed = VaultCodec.seal(VaultCodec.changePassword(vault, pw("new")))
        val e = assertFailsWith<VaultException.KeyEpochMismatch> { VaultCodec.openWithLocalUnlockSecret(rekeyed, secret) }
        assertEquals(2L, e.found)
        assertEquals(1L, e.expected)
        // A fresh export at the new epoch works.
        val reopened = VaultCodec.open(rekeyed, pw("new"))
        assertEquals(reopened.content, VaultCodec.openWithLocalUnlockSecret(rekeyed, reopened.exportLocalUnlockSecret()).content)
    }

    @Test
    fun aWrongOrMalformedLocalUnlockSecretIsRefused() {
        val vault = sample()
        val file = VaultCodec.seal(vault)
        val secret = vault.exportLocalUnlockSecret()
        val wrongKey = secret.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 1).toByte() }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.openWithLocalUnlockSecret(file, wrongKey) }
        val otherVault = sample()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> {
            VaultCodec.openWithLocalUnlockSecret(file, otherVault.exportLocalUnlockSecret())
        }
        for (bad in listOf(ByteArray(0), secret.copyOf(secret.size - 1), secret + byteArrayOf(0), secret.copyOf().also { it[0] = 0 }, secret.copyOf().also { it[4] = 9 })) {
            assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.openWithLocalUnlockSecret(file, bad) }
        }
        // The caller's secret is not modified by an open.
        val before = secret.copyOf()
        VaultCodec.openWithLocalUnlockSecret(file, secret).close()
        assertContentEquals(before, secret)
    }

    @Test
    fun theLocalUnlockSecretOfAClosedVaultCannotBeExported() {
        val vault = sample()
        vault.close()
        assertFailsWith<IllegalStateException> { vault.exportLocalUnlockSecret() }
    }

    // ------------------------------------------------------------------ rotation, slots, escape hatch

    @Test
    fun removingAPasswordSlotRotatesAndTheRemainingPasswordStillOpens() {
        val one = sample()
        val two = VaultCodec.addPasswordSlot(one, pw("second"), fast)
        assertEquals(2, two.slots.size)
        assertEquals(1L, two.keyEpoch)
        assertEquals(2L, two.headerRevision)
        val ids = two.slotIds
        assertFailsWith<IllegalArgumentException> { VaultCodec.removeSlot(two, ids[0]) } // password of slot 2 missing
        val removed = VaultCodec.removeSlot(two, ids[0], mapOf(ids[1] to pw("second")))
        val file = VaultCodec.seal(removed)
        assertEquals(2L, removed.keyEpoch)
        assertEquals(1, removed.slots.size)
        VaultCodec.open(file, pw("second")).close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(file, pw("pw")) }
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(file, two))
        assertFailsWith<VaultException.NoSuchSlot> { VaultCodec.removeSlot(two, "missing") }
        assertFailsWith<IllegalArgumentException> { VaultCodec.removeSlot(one, one.slotIds.single()) }
    }

    @Test
    fun openWithDataKeyAdoptsTheSlotsOfASameEpochFile() {
        val v = sample()
        val withSecond = VaultCodec.addPasswordSlot(v, pw("second"), fast)
        val reopened = VaultCodec.openWithDataKey(VaultCodec.seal(withSecond), v)
        assertEquals(v.content, reopened.content)
        assertEquals(2, reopened.slots.size)
        assertEquals(2L, reopened.headerRevision)
        assertFailsWith<VaultException.DifferentVault> { VaultCodec.openWithDataKey(VaultCodec.seal(withSecond), sample()) }
    }

    @Test
    fun migrateToNewVaultKeepsLiveRecordsAtRevisionOneUnderANewId() {
        val v = sample()
        val editor = VaultEditor(v.content, "A")
        editor.upsertSnippet(SnippetPayload("gone", "x"), id = "s2")
        editor.delete("s2")
        val big = v.withContent(editor.content)
        val migrated = VaultCodec.migrateToNewVault(big, pw("fresh"), fast)
        assertNotEquals(v.vaultId, migrated.vaultId)
        assertEquals(1, migrated.content.records.size)
        assertEquals(1L, migrated.content.records.single().revision)
        assertEquals(1L, migrated.content.revision)
        assertTrue(migrated.content.history.isEmpty())
        VaultCodec.open(VaultCodec.seal(migrated), pw("fresh")).close()
    }

    @Test
    fun recordsAboveTheContentRevisionAreRejectedOnOpenAndSeal() {
        val vault = VaultCodec.create(pw("pw"), fast)
        val bad = vault.content.copy(
            revision = 1,
            records = listOf(VaultRecord("a", RecordType.Snippet, 2, "A", 0, false, JsonObject(emptyMap()))),
        )
        assertFailsWith<VaultException.InvalidContent> { VaultCodec.seal(vault.withContent(bad)) }
        val file = VaultCodec.sealWithoutContentValidation(vault.withContent(bad))
        assertFailsWith<VaultException.InvalidContent> { VaultCodec.open(file, pw("pw")) }
    }
}
