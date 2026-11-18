# :core:vault

Encrypted credential vault for TerminalMax: record model, merge, and the on-disk format.
The binary format (version 2, the only supported one) is specified in [FORMAT.md](FORMAT.md).

* `commonMain` (pure Kotlin + kotlinx.serialization): `VaultRecord`, `VaultContent` (with `validate()`), typed
  payloads (`HostPayload`, `IdentityPayload`, `PrivateKeyPayload`, `WireGuardProfilePayload`, `KnownHostPayload`,
  `SnippetPayload`), `VaultEditor`, `mergeVaults`, `MergeResult`, `Conflict`, `Regression`, `KdfParams`,
  `VaultException`.
* `jvmCommonMain` (Android + desktop; JCA AES-GCM, BouncyCastle Argon2id, X25519 and HKDF through BouncyCastle's
  lightweight API, not JCA XDH): `VaultCodec`, `OpenVault`, `DeviceKeyPair`, `HeaderInfo`, `SlotInfo`.

```kotlin
val vault = VaultCodec.create(password)                   // new vault, 64 MiB Argon2id, key epoch 1
val editor = VaultEditor(vault.content, deviceId)
editor.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin"))
val file: ByteArray = VaultCodec.seal(vault.withContent(editor.content))
val reopened = VaultCodec.open(file, password)            // BadPasswordOrCorrupt on any failure
reopened.close()                                          // zeroes the data key

// A second device: a hardware-backed X25519 key pair, a slot for it, and no password needed later.
val pair = VaultCodec.generateDeviceKeyPair()             // store pair.privateKey in Keystore/Keychain/DPAPI
val withDevice = VaultCodec.addDeviceSlot(vault, pair.publicKey)
val onThatDevice = VaultCodec.openWithDeviceKey(VaultCodec.seal(withDevice), slotId, pair.privateKey)

// Key rotation: both of these replace the data key (key epoch + 1).
val rotated = VaultCodec.changePassword(vault, newPassword)
val trimmed = VaultCodec.removeSlot(vault, slotId, passwords = mapOf(otherSlotId to itsPassword))
```

## What changed in version 2

* A **key epoch** and a **header revision** are part of the authenticated data, so a replayed old header (an old
  password, a removed device slot) is recognisable by the sync layer, which remembers the highest values.
* **Data-key rotation**: a password change and a slot removal now replace the data key. The old password or a removed
  slot's secret cannot read or forge anything written afterwards (old copies of the file stay readable to them).
  Other password slots must be supplied with their password when rotating; device slots are re-wrapped from their
  public keys.
* **X25519 device slots**: any device holding the data key can wrap a new key for all other devices.
* A **fresh content key per write** (HKDF from the data key and a random write salt), so there is no nonce budget.
* **Bounded key derivation**: at most 2 password slots, per-slot and total cost limits, all checked before the first
  Argon2 call. The slot that opened the vault last (`preferredSlotId`) is tried first.
* **Content validation** on open, before merge and before seal: revision bounds, unique non-empty ids, one id one
  type, record count and size caps. Failures surface as `VaultException.InvalidContent`.
* **Passwords** are NFC-normalised and encoded as strict UTF-8 (an unpaired surrogate is an error).
* Version 1 files are not supported.

## Merge rules

`mergeVaults(base, local, remote, localDeviceId)` is a pure join: per record id the **highest** version under
`(revision, deviceId, canonical JSON)` wins, whatever the base says. Wall-clock time is never used. The result is
commutative, associative and idempotent for the record set, so devices converge whatever the order of syncs.
The optional `base` is only used to classify what happened:

* an ordinary fast-forward: nothing is reported;
* both sides changed the record: a `Conflict`; the loser is kept in `history`;
* a side offers a version older than the base (or lacks a record the base had) although it did not change it:
  a `Regression`, the sign of a stale file or a replay. The newer version is kept and the result must be pushed back;
* one id with two record types: always a `Conflict`.

When a tombstone wins, older history entries of that id are dropped, so a deleted secret does not linger in
history. History is capped at 200 entries and about 1 MiB. A new revision is `max(record, content) + 1`.
Vaults with different ids, a newer schema or content that breaks the validation rules are rejected.

## Threat model

Protects confidentiality and integrity of vault contents against anyone who can read or modify the stored file
(a malicious or compromised file server, a stolen backup). An attacker holding the file can attempt offline
password guessing; Argon2id cost is the defence, and a weak password stays weak. The file leaks its size, the number
and type of key slots, the KDF parameters, the key epoch and the header revision.

What the format does **not** do by itself:

* It does not detect rollback to an older authentic file. It supplies authenticated key epoch and header revision, and
  the sync layer remembers the highest values; the first file a device ever sees is accepted on trust.
* Rotation cannot take back copies the removed party already has.
* Two devices that rotate the key independently produce files the other cannot read; one of them has to re-open
  the vault.
* It does not protect against malware on a device that has the vault open. Decrypted records are ordinary JVM
  strings and cannot be wiped; JCA/BouncyCastle key objects are zeroed where the library allows it, and some
  intermediate copies (for example the `String` of a normalised password) are not wipeable.

## Not done yet

* Tombstone garbage collection (`pruneTombstones` exists but is unused).
* Secure storage of the device key (Android Keystore / DPAPI / macOS Keychain); the codec only takes and returns
  raw key bytes.
* Known-answer tests for a complete vault file and for Argon2id (RFC 9106 vectors); the primitives were checked
  against RFC 7748, RFC 5869 and the AES-GCM test vectors, and the format is exercised by round-trip and tamper
  tests.
* UI, password-change flow and file-backed storage of the vault itself.
