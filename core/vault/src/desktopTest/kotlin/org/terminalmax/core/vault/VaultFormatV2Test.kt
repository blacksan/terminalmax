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

    // ---- golden data: produced by core/vault/src/desktopTest/resources/golden/GoldenGen.java, a stand-alone encoder
    // ---- that re-implements the format from FORMAT.md with javax.crypto and BouncyCastle's Argon2id only and shares
    // ---- no code with the codec. Re-run it to reproduce these constants byte for byte. Epoch 1 key = 00..1f,
    // ---- epoch 2 key = 80..9f.
    private val goldenEpoch1 =
        "544d58560002000001a47b226b6466223a226172676f6e326964222c227661756c744964223a22676f6c64656e2d7661756c" +
        "74222c226b657945706f6368223a312c22736c6f7473223a5b7b226964223a2270772d303132333435363738396162636465" +
        "66222c2274797065223a2270617373776f7264222c2273616c74223a2241514944424155474277674a4367734d4451345045" +
        "413d3d222c226d656d6f72794b6942223a383139322c22697465726174696f6e73223a312c22706172616c6c656c69736d22" +
        "3a312c226e6f6e6365223a2245524954464255574678675a47687363222c22777261707065644b6579223a22302f696e5743" +
        "4654552b386b5630694238586d416b6a746141534f33694f37466e6c516a5051474274483775636351532b742f5650775166" +
        "7657426972703956227d5d2c22777269746553616c74223a224b536f724c4330754c7a41784d6a4d304e5459334f446b364f" +
        "7a7739506a394151554a44524556475230673d222c226b6579436f6d6d6974223a222b4656725050706277426f652f4a6d54" +
        "336834703375397166755436366d6b4b2b77567834736843476e383d227d38f3e9bcdee6a1ddd42ac6a3ae10020096f23a91" +
        "b90918f5c7654750ab06975fa28910517e4fff94dbb4d4114a8915093c2975b0be3a5d67d2841a7ae0cf54e08c26414ae344" +
        "c6781ab28bf30af381b05b48de5bde10d300e44340b6c6330adfed51cf9a11053a5983cb777fbc3b69de80bef9a742911560" +
        "92cdeabd02459c0c56288fa69340b1df9a120a4807760c071900cf488f30acdd9c41753533f1701ad23b69fe2f5a0d5bf848" +
        "260de931e496be667e079b7ab8bebf6df32e511f4c36533335711769487584f630fe8043d764c330eadc277490eb358d041e" +
        "fb011fb66c10c4dc9c2b33860f263e4a0b13efba229aa0448b5b31da"
    private val goldenEpoch2 =
        "544d58560002000001df7b226b6466223a226172676f6e326964222c227661756c744964223a22676f6c64656e2d7661756c" +
        "74222c226b657945706f6368223a322c22736c6f7473223a5b7b226964223a2270772d303132333435363738396162636465" +
        "66222c2274797065223a2270617373776f7264222c2273616c74223a22417751464267634943516f4c4441304f4478415245" +
        "673d3d222c226d656d6f72794b6942223a383139322c22697465726174696f6e73223a312c22706172616c6c656c69736d22" +
        "3a312c226e6f6e6365223a22457851564668635947526f6248423065222c22777261707065644b6579223a22536642453561" +
        "353158352f6441503641337246554b515657626b755a564879373964536164446e4642365848614d31364a57574b44567a41" +
        "443861435345584b227d5d2c22777269746553616c74223a224b7977744c6938774d54497a4e4455324e7a67354f6a733850" +
        "54342f5145464351305246526b644953556f3d222c226b6579436f6d6d6974223a2270676e42445573694c48444c71427a63" +
        "6f724c544f4f37486c447557505a4966345169613748784f524a673d222c2265706f63684c696e6b223a2256304d764f7773" +
        "47464e6a6b356a524d7476417473474f704d7241302b714f4e566e5367336b7a423472513d227d51d37fdfc419ce5c2b8a94" +
        "2d17292c33b12a1f03162da4611ad792adbfce15830d62f0b1a15694314884c850f0c5381e2ba1a2cd8d3e31baf92800b2cb" +
        "781c90e0907b52df9a1603900d433034d27de95985f60859e3f95bb83e7edad62af9d199f2f7f40674fe9d775b018f0436bd" +
        "af1349dd8c8f28001d5789cbb66517abdbd1f7e79ee75691e818e30a27d5e9070047df843c6dd9948b9214bd3dbea7200561" +
        "d3e03db6b72985430afa980639065ebac99e1e7d835fab479b9706d91a3ee562bc6000a1d2447a802f131654222e43cbe65a" +
        "dbb608f4196c12f7c134613cd6639a5f001fffb544b17f3bbe1f959b9a205617fa5ce0c237e89cca"
    private val goldenUnicodeEpoch1 =
        "544d58560002000001a07b226b6466223a226172676f6e326964222c227661756c744964223a2276c3bc756c742de697a5e6" +
        "9cac2dc3a9222c226b657945706f6368223a312c22736c6f7473223a5b7b226964223a2270772dd0bad0bbd18ed187222c22" +
        "74797065223a2270617373776f7264222c2273616c74223a224251594843416b4b4377774e446738514552495446413d3d22" +
        "2c226d656d6f72794b6942223a383139322c22697465726174696f6e73223a312c22706172616c6c656c69736d223a312c22" +
        "6e6f6e6365223a224652595847426b614778776448683867222c22777261707065644b6579223a225a7178414f4a4c425737" +
        "79574765637a705930474b674b553870375162644d6f4c2b7a462b6b4c733247564a762b453733734c7631644a4568594b38" +
        "2f6b3271227d5d2c22777269746553616c74223a224c5334764d4445794d7a51314e6a63344f546f375044302b5030424251" +
        "6b4e4552555a4853456c4b5330773d222c226b6579436f6d6d6974223a2263704c62716f6c4d634535316c646a33684d7045" +
        "484755326e317873394e46746b57315976367257636e633d227d401bfe1784dd42a1d4e8e3ef6b72927f7dc266433aabbb79" +
        "1cd99bcd327033e08cc487e7142d3824799e3f3892c9aa42e431d535984aa261f7ae082c649f4859eb8032be4c42cf7b2065" +
        "fe81ae797b4eef69d3b9f1c1138ff426a492866fda1a9d4d9eec48993a37d4f6cb7530e512aface2623ea862c0a5f0110f10" +
        "6ca38cb25f25de9dc8f58e77525ab25a123fde78d5b6ef8faa3f5a9364a0e1d95f1be341be382bdc2f4b4207eab1e9037277" +
        "b5ce3f12ddc66e32fd14c0090096a7295fc9c9142b4e88e22d561001c599c68748c5f98b8a0736414b84aad2322f7e26b7d6" +
        "b91590c7d2e32b95253b43720ea6b02cdba9ae5b613f27d885885a"
    private val goldenUnicodeEpoch2 =
        "544d58560002000001db7b226b6466223a226172676f6e326964222c227661756c744964223a2276c3bc756c742de697a5e6" +
        "9cac2dc3a9222c226b657945706f6368223a322c22736c6f7473223a5b7b226964223a2270772dd0bad0bbd18ed187222c22" +
        "74797065223a2270617373776f7264222c2273616c74223a224277674a4367734d44513450454245534578515646673d3d22" +
        "2c226d656d6f72794b6942223a383139322c22697465726174696f6e73223a312c22706172616c6c656c69736d223a312c22" +
        "6e6f6e6365223a224678675a476873634852346649434569222c22777261707065644b6579223a227a746453466c537a514c" +
        "676a4b395a646d61376e44456d616a4f6a4f33515a5676657938663434374b754437386169726f584353487175364e784f44" +
        "372b4956227d5d2c22777269746553616c74223a224c7a41784d6a4d304e5459334f446b364f7a7739506a394151554a4452" +
        "4556475230684a536b744d5455343d222c226b6579436f6d6d6974223a224c30542f58636b532f4c7862776a51496a324c4d" +
        "645a726c66764250536153324d466b7979484749784b413d222c2265706f63684c696e6b223a22792b7665554b6e346e5769" +
        "7147775371683341376f5a4e2f50704f7673497144523653526833655458724d3d227dee6cc6f349a69ab6585fb2c493fef4" +
        "6eefbfa1635ed85bf7227e1e49dffccb80b40b11d592e2d7ca516253439e3aa8c6bbccf819c0ff3b0714d408f130c21947da" +
        "aad83ac20944cf0b07837b878c1dcb95811282c12680011464662b08ee96708d6fa2f7c0346bfe2366db8a2b38b87920de28" +
        "05cd49be968e751823048a95468778f36e3afa661fb9d4c23857ba77cd258e367cefc5acd8efe89adf5a42f5747933a9ce88" +
        "6dabc7ac1dc43ddfbcc94a60e89b3afe466bb7fa7c10fe4a3a3e9adf60d45519c6d1a0dadfe919fdb75cf6f73155b66e0d27" +
        "711ab9b1c9b1c816117f30e098a4b1b047388957dc1d768eb2415545d2685e936c411f7385590d"
    private val goldenGcm =
        "376eb772ab91a763f94c292dc581ba85c94d2a6417dc232a33"

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

    @Test
    fun theUnicodeGoldenFilesPinByteLengthPrefixesNfcPasswordsAndNonAsciiIds() {
        val vaultId = "v\u00fcult-\u65e5\u672c-\u00e9"
        val nfd = "cafe\u0301 p\u00e4ss-\uD83D\uDD11" // typed decomposed
        val nfc = "caf\u00e9 p\u00e4ss-\uD83D\uDD11"
        assertNotEquals(nfd, nfc)
        val e1 = hex(goldenUnicodeEpoch1)
        val e2 = hex(goldenUnicodeEpoch2)
        // lp(vaultId) and lp(slotId) are BYTE lengths: an encoder that used character counts would not open these.
        val opened1 = VaultCodec.open(e1, pw(nfd))
        assertEquals(vaultId, opened1.vaultId)
        assertEquals(listOf("pw-\u043a\u043b\u044e\u0447"), opened1.slotIds)
        VaultCodec.open(e1, pw(nfc)).close()
        val opened2 = VaultCodec.open(e2, pw(nfc))
        assertEquals(2L, opened2.keyEpoch)
        assertEquals("uname -a", ((opened2.content.records.single().payload["command"]) as JsonPrimitive).content)
        assertContentEquals(seq(0x80, 32), secretKeyOf(opened2.exportLocalUnlockSecret()))
        // The link (HMAC over lp(vaultId) with a byte length) verifies from the epoch-1 key.
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(e2, opened1))
        // The cheap key-only path, with a non-ASCII vault id in the secret.
        val secret = VaultCodec.encodeLocalUnlockSecret(vaultId, 2L, seq(0x80, 32))
        assertEquals(opened2.content, VaultCodec.openWithLocalUnlockSecret(e2, secret).content)
        // The same password, composed or decomposed, wrong in one character: refused.
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(e1, pw(nfc + "x")) }
    }

    @Test
    fun argon2idMatchesTheOfficialRfc9106Vector() {
        // RFC 9106 section 5.3 (Argon2id test vector): p = 4 lanes, tag length 32, m = 32 KiB, t = 3, version 0x13,
        // password 32 x 0x01, salt 16 x 0x02, secret 8 x 0x03, associated data 12 x 0x04.
        val tag = VaultCrypto.argon2idRaw(
            password = ByteArray(32) { 0x01 },
            salt = ByteArray(16) { 0x02 },
            secret = ByteArray(8) { 0x03 },
            associatedData = ByteArray(12) { 0x04 },
            iterations = 3,
            memoryKiB = 32,
            parallelism = 4,
            outputLength = 32,
        )
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", toHex(tag))
    }

    // ------------------------------------------------------------------ T-B1: the header is immutable within an epoch

    /** Decrypts [file] with [key] and re-seals it under [transform]ed header text: what a holder of the data key can do. */
    private fun forgeWithKey(file: ByteArray, key: ByteArray, newWriteSalt: ByteArray = seq(0xA0, 32), transform: (String) -> String): ByteArray {
        val header = headerText(file)
        val epoch = Regex("\"keyEpoch\":(\\d+)").find(header)!!.groupValues[1].toLong()
        val oldSalt = java.util.Base64.getDecoder().decode(Regex("\"writeSalt\":\"([^\"]*)\"").find(header)!!.groupValues[1])
        val oldHeaderBytes = header.toByteArray(Charsets.UTF_8)
        val cipher = file.copyOfRange(10 + oldHeaderBytes.size, file.size)
        val plain = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(hkdf(key, oldSalt, "TMXV2 content".toByteArray() + u32(epoch), 32), "AES"), GCMParameterSpec(128, ByteArray(12)))
            updateAAD(file.copyOfRange(0, 6) + oldHeaderBytes)
            doFinal(cipher)
        }
        val newHeader = transform(header).replace(
            Regex("\"writeSalt\":\"[^\"]*\""), "\"writeSalt\":\"" + java.util.Base64.getEncoder().encodeToString(newWriteSalt) + "\"",
        ).toByteArray(Charsets.UTF_8)
        val ct = gcm(hkdf(key, newWriteSalt, "TMXV2 content".toByteArray() + u32(epoch), 32), ByteArray(12), file.copyOfRange(0, 6) + newHeader, plain)
        return file.copyOfRange(0, 6) + u32(newHeader.size.toLong()) + newHeader + ct
    }

    /** A slot that wraps [key] under [password] (what the holder of the data key can add). Re-implements the slot AAD. */
    private fun attackerSlot(key: ByteArray, password: String, vaultId: String, epoch: Long, slotId: String): String {
        val salt = seq(0x60, 16)
        val nonce = seq(0x70, 12)
        val slotKey = VaultCrypto.argon2id(pw(password), salt, fast)
        fun lp(x: String) = x.toByteArray().let { byteArrayOf((it.size shr 8).toByte(), it.size.toByte()) + it }
        val aad = "TMXV".toByteArray() + byteArrayOf(0, 2) + lp(vaultId) + u32(epoch) + lp(slotId) + lp("password") + salt +
            u32(8192) + u32(1) + u32(1)
        val b64 = java.util.Base64.getEncoder()
        return "{\"id\":\"$slotId\",\"type\":\"password\",\"salt\":\"${b64.encodeToString(salt)}\"," +
            "\"memoryKiB\":8192,\"iterations\":1,\"parallelism\":1,\"nonce\":\"${b64.encodeToString(nonce)}\"," +
            "\"wrappedKey\":\"${b64.encodeToString(gcm(slotKey, nonce, aad, key))}\"}"
    }

    private val slotObject = Regex("\\{\"id\":\"pw-[0-9a-f]{16}\",\"type\":\"password\"[^{}]*\\}")

    @Test
    fun aSameEpochFileWithASubstitutedSlotIsAuthenticButRefusedByTheDataKeyOpen() {
        val v = sample()
        val file = VaultCodec.seal(v)
        val key = secretKeyOf(v.exportLocalUnlockSecret())
        val forged = forgeWithKey(file, key) { h ->
            h.replace(slotObject, attackerSlot(key, "attacker pw", v.vaultId, 1L, "pw-attacker"))
        }
        // The forgery is real: the attacker's password opens it (so the attack would lock the user out)...
        VaultCodec.open(forged, pw("attacker pw")).close()
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.open(forged, pw("pw")) }
        // ... and the key holder's own data-key open refuses it before decrypting anything.
        assertFailsWith<VaultException.HeaderMismatchSameEpoch> { VaultCodec.openWithDataKey(forged, v) }
        assertFalse(VaultCodec.hasSameHeaderAs(forged, v))
        // The genuine file (and a re-seal of it, with a fresh write salt) is accepted.
        assertEquals(v.content, VaultCodec.openWithDataKey(file, v).content)
        assertEquals(v.content, VaultCodec.openWithDataKey(VaultCodec.seal(v), v).content)
        assertTrue(VaultCodec.hasSameHeaderAs(VaultCodec.seal(v), v))
        // The user's password still opens the original.
        VaultCodec.open(file, pw("pw")).close()
    }

    @Test
    fun aSameEpochFileWithAnAddedSlotIsSimplyInvalid() {
        val v = sample()
        val file = VaultCodec.seal(v)
        val key = secretKeyOf(v.exportLocalUnlockSecret())
        val forged = forgeWithKey(file, key) { h ->
            h.replace(slotObject) { m -> m.value + "," + attackerSlot(key, "attacker pw", v.vaultId, 1L, "pw-attacker") }
        }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.open(forged, pw("attacker pw")) }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.openWithDataKey(forged, v) }
        assertFailsWith<VaultException.InvalidFormat> { VaultCodec.inspect(forged) }
    }

    @Test
    fun anInflatedHeaderRevisionFieldIsNowAnUnknownFieldAndTheFormatHasNoSuchNumber() {
        val v = sample()
        val file = VaultCodec.seal(v)
        val key = secretKeyOf(v.exportLocalUnlockSecret())
        assertFalse(headerText(file).contains("headerRevision"))
        for (value in listOf("2", "9007199254740991")) {
            val forged = forgeWithKey(file, key) { it.replace("\"keyEpoch\":1", "\"keyEpoch\":1,\"headerRevision\":$value") }
            assertFailsWith<VaultException> { VaultCodec.openWithDataKey(forged, v) }
            assertFailsWith<VaultException> { VaultCodec.open(forged, pw("pw")) }
        }
        // And a rotation still works afterwards: there is no counter that could be exhausted.
        VaultCodec.changePassword(v, pw("next")).close()
    }

    @Test
    fun aSameEpochFileUnderAnotherKeyIsAKeyMismatchNotAHeaderMismatch() {
        val v = sample()
        val competing = VaultCodec.create(pw("evil"), fast, vaultId = v.vaultId)
        val file = VaultCodec.seal(competing)
        assertFailsWith<VaultException.KeyMismatchSameEpoch> { VaultCodec.openWithDataKey(file, v) }
        // The password of the competing file opens it, which is the reopen path of the sync layer.
        assertEquals(1L, VaultCodec.open(file, pw("evil")).keyEpoch)
    }

    @Test
    fun aRotationChangesThePasswordSlotAndEvenJustTheKdfParametersAreARotation() {
        val v = sample()
        val slotId = v.slotIds.single()
        val file1 = VaultCodec.seal(v)
        val bigger = KdfParams(memoryKiB = 16 * 1024, iterations = 1, parallelism = 1)
        val v2 = VaultCodec.changePassword(v, pw("pw"), kdf = bigger) // same password, other parameters
        val file2 = VaultCodec.seal(v2)
        assertEquals(2L, v2.keyEpoch)
        assertEquals(listOf(slotId), v2.slotIds, "the slot keeps its id")
        assertTrue(headerText(file2).contains("\"memoryKiB\":16384"))
        assertFalse(v.dataKey().contentEquals(v2.dataKey()), "a fresh data key")
        assertEquals(EpochLinkStatus.Verified, VaultCodec.verifyEpochLink(file2, v))
        VaultCodec.open(file2, pw("pw")).close()
        assertFailsWith<VaultException.KeyEpochMismatch> { VaultCodec.openWithDataKey(file2, v) }
        assertFalse(VaultCodec.hasSameHeaderAs(file2, v))
        assertTrue(VaultCodec.haveSameHeader(file1, VaultCodec.seal(v)))
        assertFalse(VaultCodec.haveSameHeader(file1, file2))
    }

    @Test
    fun aReplacementRotationCanOutrankAForeignEpochAndIsThenNotChainVerified() {
        val v = sample()
        val jump = VaultCodec.changePassword(v, pw("pw"), atLeastEpoch = 7L)
        assertEquals(7L, jump.keyEpoch)
        val file = VaultCodec.seal(jump)
        assertEquals(EpochLinkStatus.Unverified, VaultCodec.verifyEpochLink(file, v), "the chain is one step at a time")
        VaultCodec.open(file, pw("pw")).close()
        assertEquals(2L, VaultCodec.changePassword(v, pw("x"), atLeastEpoch = 1L).keyEpoch, "never below epoch + 1")
    }

    // ------------------------------------------------------------------ fingerprint, password check, OOM, strict ids

    @Test
    fun theFingerprintIdentifiesVaultEpochAndKeyAndIsComparableAcrossDevices() {
        val v = sample()
        val f = v.fingerprint
        assertTrue(Regex("[0-9A-F]{4}(-[0-9A-F]{4}){5}").matches(f), f)
        // Independent computation: first 12 bytes of SHA-256(vaultId | epoch | keyCommit).
        val commit = java.util.Base64.getDecoder().decode(
            Regex("\"keyCommit\":\"([A-Za-z0-9+/=]+)\"").find(headerText(VaultCodec.seal(v)))!!.groupValues[1],
        )
        val digest = java.security.MessageDigest.getInstance("SHA-256")
            .digest(v.vaultId.toByteArray() + "|1|".toByteArray() + commit)
        assertEquals(toHex(digest.copyOf(12)).uppercase().chunked(4).joinToString("-"), f)
        // The same value from the password, from the local secret and from another seal; another after a rotation.
        val file = VaultCodec.seal(v)
        assertEquals(f, VaultCodec.open(file, pw("pw")).fingerprint)
        assertEquals(f, VaultCodec.openWithLocalUnlockSecret(file, v.exportLocalUnlockSecret()).fingerprint)
        assertEquals(f, VaultCodec.open(VaultCodec.seal(v), pw("pw")).fingerprint)
        val rotated = VaultCodec.changePassword(v, pw("pw"))
        assertNotEquals(f, rotated.fingerprint)
        assertNotEquals(f, sample().fingerprint)
        assertTrue(v.hasSameKeyAs(VaultCodec.open(file, pw("pw"))))
        assertFalse(v.hasSameKeyAs(rotated))
    }

    @Test
    fun verifyPasswordChecksTheSlotOfTheVaultsOwnHeader() {
        val v = sample()
        assertTrue(VaultCodec.verifyPassword(v, pw("pw")))
        assertFalse(VaultCodec.verifyPassword(v, pw("other")))
        assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.verifyPassword(v, pw("pw"), memoryCeilingKiB = 8 * 1024 - 1) }
    }

    @Test
    fun anOutOfMemoryErrorDuringKeyDerivationIsReportedAsKdfCostTooHigh() {
        val file = VaultCodec.seal(sample())
        VaultCrypto.kdfObserver = { throw OutOfMemoryError("simulated") }
        try {
            assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.open(file, pw("pw")) }
            assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.changePassword(sample(), pw("new")) }
            assertFailsWith<VaultException.KdfCostTooHigh> { VaultCodec.verifyPassword(sample(), pw("pw")) }
        } finally {
            VaultCrypto.kdfObserver = null
        }
    }

    @Test
    fun theLocalUnlockSecretRefusesAVaultIdThatIsNotStrictUtf8() {
        val v = sample()
        val file = VaultCodec.seal(v)
        val secret = v.exportLocalUnlockSecret()
        // Same length, but the first two id bytes become the invalid sequence C3 28.
        val broken = secret.copyOf().also { it[11] = 0xC3.toByte(); it[12] = 0x28 }
        assertFailsWith<VaultException.BadPasswordOrCorrupt> { VaultCodec.openWithLocalUnlockSecret(file, broken) }
        val before = secret.copyOf()
        VaultCodec.openWithLocalUnlockSecret(file, secret).close()
        assertContentEquals(before, secret)
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
