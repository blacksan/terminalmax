# :core:vault

Encrypted credential vault for TerminalMax: record model, merge, and the on-disk format.
The binary format (version 2, the only supported one) is specified in [FORMAT.md](FORMAT.md).

* `commonMain` (pure Kotlin + kotlinx.serialization): `VaultRecord`, `VaultContent` (with `validate()`), typed
  payloads (`HostPayload`, `IdentityPayload`, `PrivateKeyPayload`, `WireGuardProfilePayload`, `KnownHostPayload`,
  `SnippetPayload`), `VaultEditor`, `mergeVaults`, `MergeResult`, `Conflict`, `Regression`, `KdfParams`,
  `VaultException`, `MAX_REVISION_JUMP`, `REVISION_HEADROOM`.
* `jvmCommonMain` (Android + desktop; JCA AES-GCM and HMAC, BouncyCastle Argon2id and HKDF through its lightweight
  API): `VaultCodec`, `OpenVault`, `HeaderInfo`, `SlotInfo`, `EpochLinkStatus`.

```kotlin
val vault = VaultCodec.create(password)                   // new vault, 64 MiB Argon2id, key epoch 1
val editor = VaultEditor(vault.content, deviceId)
editor.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin"))
val file: ByteArray = VaultCodec.seal(vault.withContent(editor.content))
val reopened = VaultCodec.open(file, password)            // BadPasswordOrCorrupt on any failure
reopened.close()                                          // zeroes the data key

// Per-device convenience unlock: the secret IS the data key; keep it only in the Keystore / Keychain / DPAPI.
val secret = reopened.exportLocalUnlockSecret()
val again = VaultCodec.openWithLocalUnlockSecret(file, secret)   // KeyEpochMismatch once the vault has been re-keyed

// Key rotation: both of these replace the data key (key epoch + 1, linked to the previous epoch).
val rotated = VaultCodec.changePassword(vault, newPassword)
val trimmed = VaultCodec.removeSlot(vault, slotId, passwords = mapOf(otherSlotId to itsPassword))
```

Most applications use `:core:sync`'s `VaultSession`, which wraps this codec together with persistence and sync.

## What version 2 is

* **Password slots only** (at most 2). There are no device or public-key slots: with a public-key slot anyone who can
  read the header could mint a key epoch honest devices would adopt (FORMAT.md explains this). Convenience unlock is
  a local secret that a device keeps in its own secure storage, outside the file.
* A **key epoch** and a **header revision** are part of the authenticated data, so a replayed old header (an old
  password, a removed slot) is recognisable by the sync layer, which remembers the highest values.
* **Data-key rotation**: a password change and a slot removal replace the data key. The old password cannot read or
  forge anything written afterwards (old copies of the file stay readable to its holder). Other password slots must
  be supplied with their password when rotating.
* **Key commitment and epoch chain**: the header commits to the data key, and every epoch above 1 carries an HMAC
  under a key derived from the previous epoch's data key. A device can tell "re-keyed by a holder of my key" from "a
  file that merely claims a higher epoch" (`VaultCodec.verifyEpochLink`, `SyncWarning.KeyEpochChainUnverified`). The
  link does not cover the slots (FORMAT.md).
* A **fresh content key per write** (HKDF from the data key and a random write salt), so there is no nonce budget.
* **Bounded key derivation**: at most 2 password slots, default 64 MiB (ceiling 128 MiB on a reader), per-slot and
  total cost limits, all checked before the first Argon2 call. The slot that opened the vault last
  (`preferredSlotId`) is tried first.
* **Content validation** on open, before merge and before seal: revision bounds, no record revision above the
  content revision, unique non-empty ids, one id one type, record count and size caps (`InvalidContent`).
* **Passwords** are NFC-normalised and encoded as strict UTF-8 (an unpaired surrogate is an error).
* Version 1 files are not supported.

## Merge rules

`mergeVaults(base, local, remote, localDeviceId)` takes, per record id, the **highest** version under
`(revision, deviceId, canonical JSON)`, whatever the base says; wall-clock time is never used. That makes the record
set a join (commutative, associative, idempotent), so devices converge whatever the order of syncs. The optional
`base` is only used to *classify* what happened, never to choose:

* the lower side is the base version: an ordinary fast-forward, nothing reported;
* the lower side is already in either input's history: nothing is reported again (so merging a merge result is
  quiet), unless the base had also seen it, which is a `Regression`;
* the lower side is something this device provably saw before (in the base's records or history) and did not change:
  a `Regression`, the sign of a stale file or a replay; it is not kept in history again, and the newer version must
  be pushed back;
* anything else is a `Conflict` and the loser is kept in `history`. That includes both sides editing the record, two
  devices writing **the same revision**, an unseen loser that is below the base revision, and one id with two record
  types. An older version this device cannot prove it saw is never dropped silently;
* a record that one side lacks although the base had it is a `Regression` of that side.

When a tombstone wins, older history entries of that id are dropped, so a deleted secret does not linger. History is
a capped union (200 entries, about 1 MiB): it converges but is not associative. A new revision is
`max(record, content) + 1`. Vaults with different ids, a newer schema or content that breaks the validation rules are
rejected.

## Threat model

Protects confidentiality and integrity of vault contents against anyone who can read or modify the stored file
(a malicious or compromised file server, a stolen backup). An attacker holding the file can attempt offline
password guessing; Argon2id cost is the defence, and a weak password stays weak. The file leaks its size, the number
and type of key slots, the KDF parameters, the key epoch and the header revision.

What the format does **not** do by itself:

* It does not detect rollback to an older authentic file. It supplies authenticated key epoch and header revision, and
  the sync layer remembers the highest values; the first file a device ever sees is accepted on trust.
* Rotation cannot take back copies the removed party already has, and the epoch chain only proves that a re-key was
  made by someone who held the previous key, not that they were still authorised to.
* Two devices that rotate the key independently produce files the other cannot read; one of them has to re-open
  the vault.
* It does not protect against malware on a device that has the vault open. Decrypted records are ordinary JVM
  strings and cannot be wiped; JCA/BouncyCastle key objects are zeroed where the library allows it, and some
  intermediate copies (for example the `String` of a normalised password) are not wipeable.

## Not done yet

* Tombstone garbage collection (`pruneTombstones` exists but is unused).
* Secure storage of the local unlock secret (Android Keystore / DPAPI / macOS Keychain); the codec only produces and
  consumes the raw bytes.
* Independent known-answer data for Argon2id (RFC 9106 vectors). The suite has two complete golden files from a
  separate encoder program, and the other primitives were checked against RFC 5869 and AES-GCM answers, but both
  encoder and codec use the same BouncyCastle Argon2id, and the golden files are a fixture by the same authors.
* UI and a password-change flow beyond `VaultSession`.
