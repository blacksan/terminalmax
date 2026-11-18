# TerminalMax vault file format, version 2

All integers are big-endian. The file is a single binary blob that can be stored on any dumb file server.

**Version 2 is the only supported format.** Version 1 files are not read, not converted and not written: a v1 file
is rejected with `InvalidFormat`, and a file with a version above 2 with `UnsupportedVersion`. No vaults exist in the
field yet, so there is nothing to migrate. Version 2 is still being finalised and keeps its number until the first
release; after that, any change to the container, header fields, key derivation or AAD construction needs a new
format version, and the schema version covers changes to the plaintext JSON.

```
offset  size   field
0       4      magic "TMXV" (0x54 0x4D 0x58 0x56)
4       2      format version (u16) = 2
6       4      header length H (u32), 2 <= H <= 65536
10      H      header: UTF-8 JSON, exactly the bytes that are authenticated (see below)
10+H    N      ciphertext: AES-256-GCM(contentKey, 12 zero bytes, plaintext) || 16-byte tag, N >= 16
```

## There are no device slots, and why

An earlier draft let a device hold an X25519 key pair and be a recipient of the data key through a public-key slot.
Version 2 does not have them, deliberately. A public key is not a secret and the header is readable by the file
server, so anyone who can read the file can wrap a key of their own to every public key in it. With a public-key slot
type, a party that can write the file (a hostile or compromised server) could mint a new key epoch with a data key it
chose, wrapped to the real devices' public keys, and honest devices would adopt that epoch because they can open it.
A slot that anyone can create is not a slot that proves anything about who wrote the file.

So the header holds **password slots only** (at most 2). Convenience unlock on a device (biometrics, the OS
keychain) is not part of the file: an open vault can export a *local unlock secret* (see below) that the device
keeps in its own secure storage. A password change replaces the data key, which revokes every such secret.

## Limits enforced before any key derivation

* whole file at most 8 MiB, header at most 64 KiB;
* at most 16 slots parsed and at most **2** password slots;
* every password slot: memory 8 MiB to 1 GiB (8192 to 1048576 KiB), iterations 1 to 10, parallelism 1 to 16;
* total key-derivation cost, the sum over password slots of `memoryKiB x iterations`, at most 4 x 65536 x 3
  (786432): two slots at the defaults (64 MiB, t = 3) fit with room to spare;
* a reader applies a platform memory ceiling to every slot (default **128 MiB**, `KdfParams.PLATFORM_CEILING_KIB`,
  twice the 64 MiB default; callers on small devices pass a lower one). A slot above the ceiling makes the file
  unopenable on that device (`KdfCostTooHigh`) without any derivation having been run. The Argon2 implementation is
  pure JVM and allocates its whole matrix up front, so the ceiling is a heap bound, not only a time bound.

A header that breaks a limit is rejected before the first Argon2 call, so a hostile file cannot make a device spend
unbounded time or memory. When a caller remembers which password slot opened the vault last, that slot is tried
first.

## Header

Compact JSON written in the field order below, unknown fields rejected, `epochLink` omitted (not `null`) for epoch 1:

```json
{
  "kdf": "argon2id",
  "vaultId": "<uuid>",
  "keyEpoch": 2,
  "headerRevision": 2,
  "slots": [
    {"id": "pw-<16 hex>", "type": "password", "salt": "<b64, 16 bytes>",
     "memoryKiB": 65536, "iterations": 3, "parallelism": 4,
     "nonce": "<b64, 12 bytes>", "wrappedKey": "<b64, 48 bytes>"}
  ],
  "writeSalt": "<b64, 32 bytes>",
  "keyCommit": "<b64, 32 bytes>",
  "epochLink": "<b64, 32 bytes>"
}
```

Base64 is the standard alphabet with padding. Slot ids are unique and at most 128 characters; `vaultId` is at most 128
characters. Slot `type` must be `"password"`; anything else is rejected.

* `keyEpoch` (1 to 2^32 - 1) counts how often the data key has been replaced. The data key is replaced whenever a
  password is changed and whenever a slot is removed.
* `headerRevision` (1 to 2^53 - 1) counts changes of the slot set (adding a slot, removing a slot, changing a
  password). A writer re-seals with the header of the highest `headerRevision` it has seen, so a slot change made on
  another device is not undone by an ordinary content update.
* `writeSalt` is fresh random data for every write.
* `keyCommit` and `epochLink` are described under *Key commitment and the epoch chain*.
* Readers (the sync layer) persist the highest `keyEpoch`, `headerRevision` and content revision per `vaultId` and
  reject a file with a lower value as a rollback. The format only provides the authenticated numbers; enforcing the
  floors is the sync layer's job, and a device's first sight of a vault is accepted on trust.

## Keys

* The **data key** is 32 random bytes per key epoch. Only a password change or a slot removal creates a new one (see
  *Rotation*).
* **Password**: the caller's characters are normalised to Unicode **NFC** (`java.text.Normalizer`), then encoded
  as strict UTF-8. An unpaired surrogate is an error (`IllegalArgumentException`), never silently replaced, so two
  different passwords cannot derive the same key. A password typed with a composed character and the same password
  typed with a decomposed character open the same vault. Intermediate buffers are zeroed; the `String` produced by
  the normaliser for a password that was not already NFC cannot be wiped.
* A **password slot** wraps the data key under a slot key = Argon2id (version 0x13) over the password bytes, the
  slot's 16-byte salt and its `memoryKiB` / `iterations` / `parallelism`, output length 32 bytes.
* `wrappedKey` = AES-256-GCM(slotKey, slot nonce, data key, AAD = slotAAD) with the 16-byte tag appended (48 bytes).
* **Content key**, one per write:
  `HKDF-SHA256(ikm = dataKey, salt = writeSalt, info = "TMXV2 content" || u32(keyEpoch), length 32)`.
  The content nonce is 12 zero bytes, which is safe because each content key is used for exactly one encryption.
  The data key itself never encrypts content directly, so there is no nonce-reuse budget to track.

## Key commitment and the epoch chain

* **keyCommit** = `HKDF-SHA256(ikm = dataKey, salt = vaultId (UTF-8), info = "TMXV2 key commitment" || u32(keyEpoch),
  length 32)`. Every open compares it (constant time) with the key it obtained. A slot that unwraps to a key that
  does not match is skipped; this makes it impossible for one file to open to different contents under different
  keys, which AES-GCM alone does not rule out.
* **epochLink**, present exactly when `keyEpoch >= 2`, absent at epoch 1:
  `linkKey = HKDF-SHA256(ikm = previousDataKey, salt = vaultId (UTF-8), info = "tmx-epoch-link" || u32(previousEpoch),
  length 32)` and
  `epochLink = HMAC-SHA256(linkKey, "TMXV2 epoch link" || lp(vaultId) || u32(newEpoch) || newKeyCommit)`.
  Only a party that held the previous epoch's data key can produce a valid link to the next epoch. A device that
  holds epoch *n* can therefore tell a re-key by a holder of *n* (the link verifies, `VaultCodec.verifyEpochLink`
  returns `Verified`) from a file that merely claims a higher epoch (`Unverified`), without being able to decrypt
  the new epoch.
* The link covers the vault id, the new epoch and the new key commitment. **It does not cover the slots.** Slots are
  covered by the content tag instead (the stored header bytes are the content AAD), so changing a slot makes the
  content fail to decrypt, but a party that holds no key cannot be prevented from replacing a header and ciphertext
  wholesale with an older, authentic pair of the same epoch; that is rollback, handled by the sync layer's floors.
* The chain is one step at a time: a device two or more epochs behind cannot verify the newest file against its key
  (`Unverified`) and must be reopened with the password. The sync layer reports that as
  `SyncWarning.KeyEpochChainUnverified` instead of adopting the file silently.
* The chain proves "written by someone who held the previous key". It does not prove that the previous key's holder
  was authorised: someone whose password was removed but who still has the old data key can still link a new epoch to
  it. Removal protects what is written after a rotation that the removed party did not take part in, not a party
  that is already inside and cooperating with the server.

## Local unlock secret

`OpenVault.exportLocalUnlockSecret()` returns a small blob that holds the current data key:

```
"TMXK" (4) | u8 version = 1 | u32 keyEpoch | lp(vaultId) | dataKey (32)
```

It is **the key itself**, not a hash or a wrapped value. The caller keeps it only in platform secure storage
(Android Keystore wrapping, macOS Keychain, Windows DPAPI), never in the synced vault, a log or a backup, and zeroes it
after use. `VaultCodec.openWithLocalUnlockSecret(bytes, secret)` opens a file with it without any key derivation. It
works only for a file of the **same key epoch** and a matching `keyCommit`; a file of another epoch fails with
`KeyEpochMismatch`, which is how a device is revoked after a password change: the secret stops working and the UI
asks for the password. A secret cannot be used for a different vault id.

## Authenticated data

`lp(x) = u16(len(x)) || x` with x in UTF-8.

```
slotAAD    = "TMXV" || u16(2) || lp(vaultId) || u32(keyEpoch) || lp(slotId) || lp(type) ||
             salt(16) || u32(memoryKiB) || u32(iterations) || u32(parallelism)
contentAAD = "TMXV" || u16(2) || header bytes exactly as stored (never a re-serialisation)
```

Because the stored header bytes are authenticated, any change to the header (slots, KDF parameters, vault id, key
epoch, header revision, write salt, key commitment, epoch link) makes the content fail to decrypt. The slot AAD binds
a wrapped key to its vault, its key epoch and its slot parameters, so a slot cannot be moved to another vault,
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
* **no record revision exceeds the content revision** (a record cannot be newer than the vault that holds it);
* record ids are unique, non-empty and at most 128 characters, and one id never occurs with two record types;
* at most 10,000 records, at most 200 history entries, each record at most 256 Ki characters of payload;
* the file stays within 8 MiB.

Further rules:

* Versions of a record are ordered by `(revision, deviceId, canonical JSON)`. `updatedAtEpochMs` is informational
  and never used for ordering. A new revision is `max(record revision, content revision) + 1` (a Lamport rule), and
  an edit that would pass 2^53 - 1 fails instead of wrapping.
* **Merge** is a join over the record set: per record id the result is the maximum under that order, so merging is
  commutative, associative and idempotent for the records. The common base only *classifies* what happened and never
  selects a lower version, so a stale or replayed input can never revert an edit. History is a capped union and is
  deterministic and convergent but not associative.
  * the lower side is the base version: ordinary fast-forward, nothing reported;
  * the lower side is already kept in either input's history: nothing reported again (so merging a merge result is
    quiet); if the base had also seen it, a *regression*;
  * the lower side is in the base's history or records and the base did not change it: a *regression*, a replay of
    something this device had seen;
  * anything else is a *conflict*, and the losing version is kept in history. This includes two devices that wrote the
    same revision, a loser below the base revision that this device has never seen, and one id with two record types.
  * a record that one side lacks although the base had it is a regression of that side.
* Sync limits what it accepts from a remote file: a content revision more than `MAX_REVISION_JUMP` (2^20) above the
  highest this device has already seen is refused, and so is one above `MAX_REVISION - REVISION_HEADROOM` (2^32 below
  the maximum) whatever the floor is. Both guard against a writer pushing the vault to a revision where it could not
  be edited again; `migrateToNewVault` is the recovery.
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
  `keyCommit`, an `epochLink` to the previous epoch and a new `writeSalt` on the next seal. **Other password slots
  can only be re-wrapped with their password**, so the caller must supply those passwords (they are verified against
  the old slots); a device that does not know them cannot rotate past them. At least one password slot must remain.
* After removal, the holder of the removed slot's password can no longer read or forge anything written afterwards by
  a device that did the rotation. Copies of the file from before the removal stay readable to that holder; no format
  can prevent that.
* `addPasswordSlot` keeps the data key and only raises `headerRevision` (at most 2 password slots).
* Two devices that rotate independently to the same epoch produce files the other cannot decrypt; sync reports that
  the vault must be re-opened with the password. The format does not merge rotations.

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
| Key (data key or local unlock secret) of another epoch than the file's | `KeyEpochMismatch` |
| Another vault id (data-key open, merge) | `DifferentVault` |
| Slot id that does not exist | `NoSuchSlot` |

A vault whose schema is newer than the app supports is never written.

## Known-answer data

`VaultFormatV2Test` holds two complete files (epoch 1, and epoch 2 with a link) produced by a separate encoder
program that re-implements the container, HKDF, the AAD construction and the AES-GCM calls on its own with plain
`javax.crypto`; they must open with the password and with the local unlock secret. Both sides use the same
BouncyCastle Argon2id implementation, so the Argon2id output itself is **not** independently checked here (RFC 9106
vectors are not in the suite). The encoder is a test fixture written by the same authors, so these vectors catch
accidental drift of the format, not a shared misreading of this document.
