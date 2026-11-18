// SPDX-License-Identifier: GPL-3.0-or-later
//
// Independent encoder for the golden vault files in VaultFormatV2Test.
//
// It re-implements format v2 (core/vault/FORMAT.md) from the specification with nothing but javax.crypto and
// BouncyCastle's Argon2id, and shares no code with :core:vault. It is a throw-away generator and is not built by
// Gradle. To reproduce (or audit) the files:
//
//     java -cp bcprov-jdk18on-<version>.jar core/vault/src/desktopTest/resources/golden/GoldenGen.java
//
// The output is the Kotlin text of the constants in VaultFormatV2Test (hex strings, 100 characters per line).
// Deterministic: every salt, nonce and key is a fixed byte sequence, so running it again prints the same bytes.
// A change of the format must change this file first, then the constants, then the codec.
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.Normalizer;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

public class GoldenGen {
    static byte[] u32(long v) { return new byte[] {(byte) (v >> 24), (byte) (v >> 16), (byte) (v >> 8), (byte) v}; }

    /** lp(x) = u16(byte length of x in UTF-8) || x (a BYTE length, not a character count). */
    static byte[] lp(String s) {
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        return cat(new byte[] {(byte) (b.length >> 8), (byte) b.length}, b);
    }

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) o.write(p, 0, p.length);
        return o.toByteArray();
    }

    static byte[] hmac(byte[] k, byte[] d) throws Exception {
        Mac m = Mac.getInstance("HmacSHA256");
        m.init(new SecretKeySpec(k, "HmacSHA256"));
        return m.doFinal(d);
    }

    /** HKDF-SHA-256 (RFC 5869), written out. */
    static byte[] hkdf(byte[] ikm, byte[] salt, byte[] info, int len) throws Exception {
        byte[] prk = hmac(salt, ikm);
        byte[] t = new byte[0];
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (int i = 1; o.size() < len; i++) {
            t = hmac(prk, cat(t, info, new byte[] {(byte) i}));
            o.write(t, 0, t.length);
        }
        return Arrays.copyOf(o.toByteArray(), len);
    }

    static byte[] gcm(byte[] k, byte[] n, byte[] aad, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "AES"), new GCMParameterSpec(128, n));
        c.updateAAD(aad);
        return c.doFinal(pt);
    }

    static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x));
        return s.toString();
    }

    static byte[] seq(int start, int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) b[i] = (byte) (start + i);
        return b;
    }

    static String b64(byte[] b) { return Base64.getEncoder().encodeToString(b); }

    /**
     * One file. The password is NFC-normalised and encoded as UTF-8 here, as the format prescribes. The header is
     * compact JSON in the documented field order (no headerRevision: the header is immutable within an epoch).
     */
    static byte[] file(String vaultId, long epoch, String slotId, byte[] key, byte[] prevKey, String password,
                       int seed, String content) throws Exception {
        byte[] salt = seq(seed, 16), nonce = seq(seed + 16, 12), writeSalt = seq(seed + 40, 32);
        byte[] pwBytes = Normalizer.normalize(password, Normalizer.Form.NFC).getBytes(StandardCharsets.UTF_8);
        Argon2Parameters p = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13).withIterations(1).withMemoryAsKB(8192)
            .withParallelism(1).withSalt(salt).build();
        Argon2BytesGenerator g = new Argon2BytesGenerator();
        g.init(p);
        byte[] slotKey = new byte[32];
        g.generateBytes(pwBytes, slotKey, 0, 32);
        byte[] magic = "TMXV".getBytes(StandardCharsets.US_ASCII), ver = {0, 2};
        byte[] slotAad = cat(magic, ver, lp(vaultId), u32(epoch), lp(slotId), lp("password"), salt,
            u32(8192), u32(1), u32(1));
        byte[] wrapped = gcm(slotKey, nonce, slotAad, key);
        byte[] vid = vaultId.getBytes(StandardCharsets.UTF_8);
        byte[] commit = hkdf(key, vid, cat("TMXV2 key commitment".getBytes(StandardCharsets.US_ASCII), u32(epoch)), 32);
        String link = "";
        if (prevKey != null) {
            byte[] linkKey = hkdf(prevKey, vid,
                cat("TMXV2 epoch link key".getBytes(StandardCharsets.US_ASCII), u32(epoch - 1)), 32);
            byte[] mac = hmac(linkKey, cat("TMXV2 epoch link".getBytes(StandardCharsets.US_ASCII), lp(vaultId),
                u32(epoch), commit));
            link = ",\"epochLink\":\"" + b64(mac) + "\"";
        }
        String header = "{\"kdf\":\"argon2id\",\"vaultId\":\"" + vaultId + "\",\"keyEpoch\":" + epoch
            + ",\"slots\":[{\"id\":\"" + slotId + "\",\"type\":\"password\",\"salt\":\"" + b64(salt)
            + "\",\"memoryKiB\":8192,\"iterations\":1,\"parallelism\":1,\"nonce\":\"" + b64(nonce)
            + "\",\"wrappedKey\":\"" + b64(wrapped) + "\"}],\"writeSalt\":\"" + b64(writeSalt)
            + "\",\"keyCommit\":\"" + b64(commit) + "\"" + link + "}";
        byte[] hb = header.getBytes(StandardCharsets.UTF_8);
        byte[] contentKey = hkdf(key, writeSalt,
            cat("TMXV2 content".getBytes(StandardCharsets.US_ASCII), u32(epoch)), 32);
        byte[] ct = gcm(contentKey, new byte[12], cat(magic, ver, hb), content.getBytes(StandardCharsets.UTF_8));
        return cat(magic, ver, u32(hb.length), hb, ct);
    }

    static String content(String vaultId, long epoch, long revision, String command) {
        return "{\"schemaVersion\":2,\"vaultId\":\"" + vaultId + "\",\"revision\":" + revision
            + ",\"records\":[{\"id\":\"s1\",\"type\":\"Snippet\",\"revision\":" + revision
            + ",\"deviceId\":\"A\",\"updatedAtEpochMs\":0,\"deleted\":false,\"payload\":{\"name\":\"up\","
            + "\"command\":\"" + command + "\"}}],\"history\":[],\"keyEpoch\":" + epoch + "}";
    }

    static void print(String name, byte[] data) {
        String h = hex(data);
        System.out.println("private val " + name + " =");
        for (int i = 0; i < h.length(); i += 100) {
            String chunk = h.substring(i, Math.min(h.length(), i + 100));
            System.out.println("    \"" + chunk + "\"" + (i + 100 < h.length() ? " +" : ""));
        }
    }

    public static void main(String[] args) throws Exception {
        String vid = "golden-vault";
        byte[] k1 = seq(0, 32), k2 = seq(0x80, 32);
        String slot = "pw-0123456789abcdef";
        print("goldenEpoch1", file(vid, 1, slot, k1, null, "golden pw one", 1, content(vid, 1, 1, "uptime")));
        print("goldenEpoch2", file(vid, 2, slot, k2, k1, "golden pw two", 3, content(vid, 2, 3, "uptime -p")));

        // Non-ASCII vault id and slot id (UTF-8 byte length != character count in lp()), and a password that is
        // typed decomposed (NFD) but must be derived from its NFC form.
        String uvid = "vüult-日本-é";
        String uslot = "pw-ключ";
        String upw = "café päss-🔑"; // NFD "e + U+0301", plus a key emoji outside the BMP
        print("goldenUnicodeEpoch1", file(uvid, 1, uslot, k1, null, upw, 5, content(uvid, 1, 1, "uname")));
        print("goldenUnicodeEpoch2", file(uvid, 2, uslot, k2, k1, upw, 7, content(uvid, 2, 4, "uname -a")));

        System.out.println("private val goldenGcm =");
        System.out.println("    \"" + hex(gcm(seq(0, 32), seq(0, 12), "aad".getBytes(), "plaintext".getBytes())) + "\"");
    }
}
