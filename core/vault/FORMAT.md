# TerminalMax vault file format, version 1

All integers are big-endian. The file is a single binary blob that can be stored on any dumb file server.

```
offset  size   field
0       4      magic "TMXV" (0x54 0x4D 0x58 0x56)
4       2      format version (u16) = 1
6       4      header length H (u32), 2 <= H <= 65536
10      H      header: UTF-8 JSON, exactly the bytes that are authenticated (see below)
10+H    N      ciphertext: AES-256-GCM(dataKey, contentNonce, plaintext) || 16-byte tag, N >= 16
```

Limits enforced before any cryptography: whole file at most 32 MiB, header at most 64 KiB.

## Header

Compact JSON, field order as written below, no unknown fields accepted in v1:

```json
{
  "kdf": "argon2id",
  "vaultId": "<uuid>",
  "slots": [
    {"id": "pw0", "type": "password", "salt": "<b64, 16 bytes>",
     "memoryKiB": 65536, "iterations": 3, "parallelism": 4,
     "nonce": "<b64, 12 bytes>", "wrappedKey": "<b64, 48 bytes>"},
    {"id": "dev1", "type": "device",
     "nonce": "<b64, 12 bytes>", "wrappedKey": "<b64, 48 bytes>"}
  ],
  "contentNonce": "<b64, 12 bytes>"
}
```

Base64 is the standard alphabet with padding. There are at most 16 slots; slot ids are unique and at most 128
characters.

## Keys

* The **data key** is 32 random bytes generated when the vault is created. It never changes (changing the
  password only re-wraps it).
* A **password slot** wraps the data key under a slot key derived with Argon2id (version 0x13) from the UTF-8
  bytes of the password, the slot's 16-byte salt and its `memoryKiB` / `iterations` / `parallelism`; output length
  32 bytes.
* A **device slot** wraps the data key under a caller-supplied 32-byte key (for example one held in the Android
  Keystore, DPAPI or the macOS Keychain). Where that key is stored is outside this format.
* `wrappedKey` = AES-256-GCM(slotKey, slot nonce, plaintext = data key) with a 16-byte tag appended (48 bytes).

KDF parameters read from a file are validated before any work is done: memory 8 MiB to 1 GiB (8192 to 1048576
KiB), iterations 1 to 10, parallelism 1 to 16. Default for new vaults: 64 MiB, t = 3, p = 4.

## Authenticated data

* Slot wrapping AAD: `"TMXV" || u16(1) || u16(len(vaultId)) || vaultId || u16(len(slotId)) || slotId`
  (UTF-8; the length prefixes make the encoding unambiguous).
* Content AAD: `"TMXV" || u16(1) || header bytes exactly as stored`. Because the stored header bytes are
  authenticated, any change to the header (slots, KDF parameters, vault id, nonce) makes the content fail to
  decrypt, and the vault id also binds each wrapped key to its vault.
* A fresh random 12-byte `contentNonce` is generated for every write. Header and ciphertext of different writes
  cannot be mixed.

## Plaintext

UTF-8 JSON of `VaultContent`:

```json
{"schemaVersion": 1, "vaultId": "<uuid>", "revision": 12,
 "records": [ { "id": "...", "type": "Host", "revision": 3, "deviceId": "...",
                "updatedAtEpochMs": 0, "deleted": false, "payload": { } } ],
 "history": [ ]}
```

* `revision` is a monotonic content revision; `vaultId` must equal the header's.
* Records are ordered by `(revision, deviceId)`. `updatedAtEpochMs` is informational and never used for ordering.
* Record types: Host, Identity, PrivateKey, WireGuardProfile, KnownHost, Snippet, Settings. Unknown types, unknown
  record-level fields and unknown payload fields are preserved byte-for-byte in meaning when a vault is rewritten.
* `history` holds the losing sides of merge conflicts (at most 200, oldest dropped).
* Deleted records stay as tombstones (`deleted: true`, empty payload). Tombstones are not garbage collected in v1.

## Errors

| Situation | Exception |
|---|---|
| Wrong password, wrong key, modified header or ciphertext, malformed header content | `BadPasswordOrCorrupt` (not distinguished) |
| Bad magic, truncated, oversized, bad header length | `InvalidFormat` |
| Format version or schema version newer than supported | `UnsupportedVersion` |
| KDF parameters out of bounds | `KdfParamsOutOfRange` |

A vault whose schema is newer than the app supports is never written.

## Versioning

Format version 1 is fixed by this document. A change to the container, header fields or AAD construction needs a
new format version; the schema version covers changes to the plaintext JSON.
