# :core:vault

Encrypted credential vault for TerminalMax: record model, three-way merge, and the on-disk format.
The binary format is specified in [FORMAT.md](FORMAT.md).

* `commonMain` (pure Kotlin + kotlinx.serialization): `VaultRecord`, `VaultContent`, typed payloads (`HostPayload`,
  `IdentityPayload`, `PrivateKeyPayload`, `WireGuardProfilePayload`, `KnownHostPayload`, `SnippetPayload`),
  `VaultEditor`, `mergeVaults`, `pruneTombstones`, `KdfParams`, `VaultException`.
* `jvmCommonMain` (Android + desktop; JCA AES-GCM and BouncyCastle Argon2id): `VaultCodec`, `OpenVault`.

```kotlin
val vault = VaultCodec.create(password)                  // new vault, 64 MiB Argon2id
val editor = VaultEditor(vault.content, deviceId)
editor.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin"))
val file: ByteArray = VaultCodec.seal(vault.withContent(editor.content))
val reopened = VaultCodec.open(file, password)           // BadPasswordOrCorrupt on any failure
reopened.close()                                         // zeroes the data key
```

## Merge rules

`mergeVaults(base, local, remote, localDeviceId)` merges per record id. Versions are ordered by
`(revision, deviceId)`; wall-clock time is never used. A record changed on one side since `base` takes that side.
Changed on both sides: the higher version wins, ties go to the lexicographically larger `deviceId`, and the loser is
appended to `history` (capped at 200) and reported as a `Conflict`. Tombstones follow the same rule. The result is
deterministic and commutative for the record set. Vaults with different ids or a newer schema are rejected.

## Threat model

Protects confidentiality and integrity of vault contents against anyone who can read or modify the stored file
(a malicious or compromised file server, a stolen backup). An attacker holding the file can attempt offline password
guessing; Argon2id cost is the defence. The file leaks its size, the number of key slots and the KDF parameters.
It does not protect against malware on a device that has the vault open, nor against rollback to an older valid
file (that is detected by the sync layer, not the format).

## Not done yet

* Tombstone garbage collection (`pruneTombstones` exists but is unused).
* Secure storage of the device key (Android Keystore / DPAPI / macOS Keychain) and of `OpenVault` in memory beyond
  zeroing the data key. Decrypted records are ordinary JVM strings and cannot be wiped.
* Data-key rotation (removing a device slot does not re-encrypt old copies of the file).
* UI, password-change flow and file-backed storage.
