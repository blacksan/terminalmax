# TerminalMax vault file format, version 2

All integers are big-endian. The file is a single binary blob that can be stored on any dumb file server.

**Version 2 is the only supported format.** Version 1 files (which had no key epoch, no header revision and
no per-write content key) are not read, not converted and not written: a v1 file is rejected with
`InvalidFormat`, and a file with a version above 2 with `UnsupportedVersion`. No vaults exist in the field yet, so there is nothing to migrate.

```
offset  size   field
0       4      magic "TMXV" (0x54 0x4D 0x58 0x56)
4       2      format version (u16) = 2
6       4      header length H (u32), 2 <= H <= 65536
10      H      header: UTF-8 JSON, exactly the bytes that are authenticated (see below)
10+H    N      ciphertext: AES-256-GCM(contentKey, 12 zero bytes, plaintext) || 16-byte tag, N >= 16
```

Limits enforced before any cryptography or key derivation:

* whole file at most 8 MiB, header at most 64 KiB;
* at most 16 slots in total and at most 2 password slots;
* every password slot: memory 8 MiB to 1 GiB (8192 to 1048576 KiB), iterations 1 to 10, parallelism 1 to 16;
* total key-derivation cost, the sum over password slots of `memoryKiB x iterations`, at most 4 x 65536 x 3
  (786432), which allows two slots at the default parameters (64 MiB, t = 3) with room to spare, or one slot at
  256 MiB with t = 3;
* a reader applies a platform memory ceiling to every slot (default 256 MiB, `KdfParams.PLATFORM_CEILING_KIB`;
  callers on small devices pass a lower one). A slot above the ceiling makes the file unopenable on that device
  (`KdfCostTooHigh`) without any derivation having been run.

A header that breaks a limit is rejected before the first Argon2 call, so a hostile file cannot make a device spend
unbounded time or memory. When a caller remembers which password slot opened the vault last, that slot is tried
first.

## Header

Compact JSON, field order as written below, unknown fields rejected:

```json
{
  "kdf": "argon2id",
  "vaultId": "<uuid>",
  "keyEpoch": 1,
  "headerRevision": 1,
  "slots": [
    {"id": "pw-<16 hex>", "type": "password", "salt": "<b64, 16 bytes>",
     "memoryKiB": 65536, "iterations": 3, "parallelism": 4,
     "nonce": "<b64, 12 bytes>", "wrappedKey": "<b64, 48 bytes>"},
    {"id": "dev-<16 hex>", "type": "device-x25519",
     "devicePublicKey": "<b64, 32 bytes>", "ephemeralPublicKey": "<b64, 32 bytes>",
     "nonce": "<b64, 12 bytes>", "wrappedKey": "<b64, 48 bytes>"}
  ],
  "writeSalt": "<b64, 32 bytes>"
}
```

Base64 is the standard alphabet with padding. Slot ids are unique and at most 128 characters; `vaultId` is at most 128
characters.

* `keyEpoch` (1 to 2^32 - 1) counts how often the data key has been replaced. The data key is replaced whenever a
  slot is removed and whenever a password is changed.
* `headerRevision` (1 to 2^53 - 1) counts changes of the slot set (adding a slot, removing a slot, changing a
  password). A writer re-seals with the header of the highest `headerRevision` it has seen, so a slot change made on
  another device is not undone by an ordinary content update.
* Readers (the sync layer) persist the highest `keyEpoch` and `headerRevision` per `vaultId` and reject a file with a
  lower value as a rollback. The format only provides the authenticated numbers; enforcing the floors is the sync
  layer's job.
* `writeSalt` is fresh random data for every write.

## Keys

* The **data key** is 32 random bytes per key epoch. A password change or a slot removal creates a new one (see
  *Rotation*); everything else keeps it.
* **Password**: the caller's characters are normalised to Unicode **NFC** (`java.text.Normalizer`), then encoded
  as strict UTF-8. An unpaired surrogate is an error (`IllegalArgumentException`), never silently replaced, so two
  different passwords cannot derive the same key. A password typed with a composed character and the same password
  typed with a decomposed character open the same vault. Intermediate buffers are zeroed; the `String` produced by
  the normaliser for a password that was not already NFC cannot be wiped.
* A **password slot** wraps the data key under a slot key = Argon2id (version 0x13) over the password bytes, the
  slot's 16-byte salt and its `memoryKiB` / `iterations` / `parallelism`, output length 32 bytes.
* A **device slot** wraps the data key to a device's long-lived **X25519** public key. The writer generates an
  ephemeral X25519 key pair per slot and stores its public half:
  `slotKey = HKDF-SHA256(ikm = X25519(ephemeralPrivate, devicePublic), salt = vaultId (UTF-8),
  info = "TMXV2 device slot", length 32)`. Any device that holds the data key can therefore wrap a new data key for
  every other device without holding their private keys. Each device keeps its X25519 private key in the Android
  Keystore, the macOS Keychain or DPAPI; where it is stored is outside this format.
* `wrappedKey` = AES-256-GCM(slotKey, slot nonce, data key, AAD = slotAAD) with the 16-byte tag appended (48 bytes).
* **Content key**, one per write:
  `HKDF-SHA256(ikm = dataKey, salt = writeSalt, info = "TMXV2 content" || u32(keyEpoch), length 32)`.
  The content nonce is 12 zero bytes, which is safe because each content key is used for exactly one encryption.
  The data key itself never encrypts content directly, so there is no nonce-reuse budget to track.

## Authenticated data

`lp(x) = u16(len(x)) || x` with x in UTF-8.

```
slotAAD    = "TMXV" || u16(2) || lp(vaultId) || u32(keyEpoch) || lp(slotId) || lp(type) ||
             password:       salt(16) || u32(memoryKiB) || u32(iterations) || u32(parallelism)
             device-x25519:  devicePublicKey(32) || ephemeralPublicKey(32)
contentAAD = "TMXV" || u16(2) || header bytes exactly as stored (never a re-serialisation)
```

Because the stored header bytes are authenticated, any change to the header (slots, KDF parameters, vault id, key
epoch, header revision, write salt) makes the content fail to decrypt. The slot AAD binds a wrapped key to its
vault, its key epoch, its slot parameters and its own public keys, so a slot cannot be moved to another vault,
another epoch or another position.

## Plaintext (schemaVersion 2)

UTF-8 JSON of `VaultContent` plus one field that mirrors the header:

```json
{"schemaVersion": 2, "vaultId": "<uuid>", "keyEpoch": 1, "revision": 12,
 "records": [ { "id": "...", "type": "Host", "revision": 3, "deviceId": "...",
                "updatedAtEpochMs": 0, "deleted": false, "payload": { } } ],
 "history": [ ]}
```

A reader rejects the file (`InvalidContent`) when any of these is violated; a writer refuses to seal such content:

* `keyEpoch` equals the header's, `vaultId` equals the header's;
* `revision` is in [0, 2^53 - 1], every record revision is in [1, 2^53 - 1];
* record ids are unique, non-empty and at most 128 characters, and one id never occurs with two record types;
* at most 10,000 records, at most 200 history entries, each record at most 256 Ki characters of payload;
* the file stays within 8 MiB.

Further rules:

* Versions of a record are ordered by `(revision, deviceId, canonical JSON)`. `updatedAtEpochMs` is informational
  and never used for ordering. A new revision is `max(record revision, content revision) + 1` (a Lamport rule), and
  an edit that would pass 2^53 - 1 fails instead of wrapping.
* **Merge** is a pure join: per record id the result is the maximum under that order. The common base only
  *classifies* what happened (fast-forward, conflict, regression) and never selects a lower version, so a stale or
  replayed input can never revert an edit.
* Record types: Host, Identity, PrivateKey, WireGuardProfile, KnownHost, Snippet, Settings. Unknown record-level
  fields and unknown payload fields are preserved when a vault is rewritten.
* `history` holds the losing sides of merge conflicts. When a tombstone wins, history entries of that id with a
  revision up to the tombstone's are dropped (so deleting a secret removes its older versions). History is capped at
  200 entries and about 1 MiB of text, oldest dropped first.
* Deleted records stay as tombstones (`deleted: true`, empty payload). Tombstones are not garbage collected.

There is no digest of the previous file inside the plaintext. Fork detection (two different files at the same
revision) is done by the sync layer from digests of files it has seen.

## Rotation

* `changePassword` and `removeSlot` **replace the data key**: `keyEpoch + 1`, `headerRevision + 1`, a new
  `writeSalt` on the next seal. Device slots are re-wrapped from their stored public keys, so no device secret is
  needed. Other **password slots can only be re-wrapped with their password**, so the caller must supply those
  passwords (they are verified against the old slots); a device that does not know them cannot rotate past them. This
  is a deliberate limit of a password-based slot.
* After removal, the holder of the removed slot's secret can no longer read or forge anything written afterwards.
  Copies of the file from before the removal stay readable to that holder; no format can prevent that.
* `addPasswordSlot` and `addDeviceSlot` keep the data key and only raise `headerRevision`.
* Two devices that rotate independently to the same epoch produce files the other cannot decrypt (the second writer
  to arrive sees `BadPasswordOrCorrupt` or a key-epoch mismatch); sync reports that the vault must be re-opened. The
  format does not merge rotations.

## Errors

| Situation | Exception |
|---|---|
| Wrong password, wrong key, modified header or ciphertext, malformed header content | `BadPasswordOrCorrupt` (not distinguished) |
| A slot unwrapped with the right secret but the content failed authentication | `IntegrityFailure` |
| Bad magic, truncated, oversized, bad header length, format version 1 (or any version below 2) | `InvalidFormat` |
| Format version above 2, or a schema version newer than supported | `UnsupportedVersion` |
| KDF parameters outside the per-field bounds | `KdfParamsOutOfRange` |
| Platform memory ceiling or total cost budget exceeded, too many password slots | `KdfCostTooHigh` |
| Authentic file whose content breaks the content rules | `InvalidContent` |
| Data key of another epoch than the file's (data-key open) | `KeyEpochMismatch` |
| Another vault id (data-key open, merge) | `DifferentVault` |
| Slot id that does not exist | `NoSuchSlot` |

A vault whose schema is newer than the app supports is never written.

## Versioning

Format version 2 is fixed by this document. A change to the container, header fields, key derivation or AAD
construction needs a new format version; the schema version covers changes to the plaintext JSON.
