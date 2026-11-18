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

// Key rotation: the only slot operation. It replaces the data key (key epoch + 1, linked to the previous epoch).
val rotated = VaultCodec.changePassword(vault, newPassword)

// What a user compares across devices before trusting a vault: six groups of four hex characters.
val fingerprint = reopened.fingerprint
```

Most applications use `:core:sync`'s `VaultSession`, which wraps this codec together with persistence and sync.

## What version 2 is

* **One password slot.** There are no device or public-key slots and no second password: with a public-key slot
  anyone who can read the header could mint a key epoch honest devices would adopt, and with several slots every
  holder of the data key could substitute one (FORMAT.md explains both). Convenience unlock is a local secret that a
  device keeps in its own secure storage, outside the file.
* **An immutable header per key epoch.** Everything but the write salt is fixed when the epoch is created; the
  **key epoch** is part of the authenticated data, so a replayed old header (an old password) is recognisable by the
  sync layer, which remembers the highest epoch and refuses a same-epoch file with another header
  (`HeaderMismatchSameEpoch`) instead of adopting it.
* **Data-key rotation**: a password change replaces the data key and is the only slot operation. The old password
  cannot read or forge anything written afterwards by a device that did the rotation (old copies of the file stay
  readable to its holder, who can also mint a linked next epoch for devices that have not seen the rotation).
  Revoking a lost device means changing the vault password **and** the WebDAV credential.
* **Key commitment and epoch chain**: the header commits to the data key, and every epoch above 1 carries an HMAC
  under a key derived from the previous epoch's data key. A device can tell "re-keyed by a holder of my key" from "a
  file that merely claims a higher epoch" (`VaultCodec.verifyEpochLink`, `SyncWarning.KeyEpochChainUnverified`). The
  link does not cover the slot, and a verified link is not "trusted" (FORMAT.md).
* A **fresh content key per write** (HKDF from the data key and a random write salt), so there is no nonce budget.
* **Bounded key derivation**: exactly one slot, default 64 MiB (ceiling 128 MiB on a reader; callers pass a lower
  one), per-field and total cost limits, all checked before the Argon2 call. Running out of memory inside the
  derivation is reported as `KdfCostTooHigh`, not as a crash.
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
password guessing; Argon2id cost is the defence, and a weak password stays weak. The file leaks its size, the KDF parameters and the key epoch.

What the format does **not** do by itself:

* It does not detect rollback to an older authentic file. It supplies the authenticated key epoch, and the sync
  layer remembers the highest values; the first file a device ever sees is accepted on trust (compare the
  fingerprint across devices).
* Rotation cannot take back copies the removed party already has, and the epoch chain only proves that a re-key was
  made by someone who held the previous key, not that they were still authorised to.
* Whoever holds the data key of an epoch (an exported local unlock secret, a compromised device) can re-seal files
  of that epoch with any header. The format cannot stop it; the sync layer refuses such a file on every device that
  holds the same key, and only the password (never the data key) opens a new epoch.
* Two devices that rotate the key independently produce files the other cannot read; the sync layer prevents this
  for its own transaction and otherwise needs the password on the losing device.
* It does not protect against malware on a device that has the vault open. Decrypted records are ordinary JVM
  strings and cannot be wiped. The data key and the derived keys held by this library are zeroed on `close()`, but
  the JCA and BouncyCastle objects built from them (`SecretKeySpec`, cipher state) hold their own copies that
  nothing here can wipe, and some intermediate copies (for example the `String` of a normalised password) are not
  wipeable either.

## Not done yet

* Tombstone garbage collection (`pruneTombstones` exists but is unused).
* Secure storage of the local unlock secret (Android Keystore / DPAPI / macOS Keychain); the codec only produces and
  consumes the raw bytes.
* Independent known-answer data for AES-GCM and HKDF beyond RFC 5869 test case 1. Argon2id is checked against the
  RFC 9106 test vector, and the golden files are reproducible from the committed
  `src/desktopTest/resources/golden/GoldenGen.java`, but that generator is a fixture by the same authors.
* UI and a password-change flow beyond `VaultSession`.
