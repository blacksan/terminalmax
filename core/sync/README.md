# :core:sync

WebDAV synchronisation of the encrypted vault file produced by `:core:vault` (format version 2).

* `commonMain`: `RemoteStore` (single vault file plus a lock file), `ServerCapabilities`, `DeleteResult`,
  `SyncEngine`, `SyncOutcome` / `SyncResult` / `SyncWarning` / `SyncOptions` / `FailureReason`, `LocalStateStore`
  with `LocalSyncState` / `VaultSyncState` / `ServerSyncState` / `ChainWarning`, `LocalView`, `VaultCodecHooks` (the
  engine's view of encryption, including `StagedHeaderChange`), `isStrongEtag` / `usableEtag`. The in-memory state
  store is `internal` (tests).
* `jvmCommonMain` (Android + desktop): **`VaultSession`** (the facade apps use) with `VaultSessionException`,
  `JoinPreview`, `SalvageResult`; `WebDavStore` (OkHttp 5), `PropfindParser`, `FileLocalStateStore`, and
  `OpenVaultCodecHooks` (internal; it holds the data key).

## Use `VaultSession`

`VaultSession` is the one thing an app should hold. It owns the local vault file, the sync state, the data key and an
OS-level lock on its directory.

```kotlin
val dir = File(context.filesDir, "vault")                       // one directory per local vault
val session = VaultSession.create(dir, password)                 // or VaultSession.open(dir, password)
session.edit { it.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin")) }   // committed to disk, then published
val store = WebDavStore("https://dav.example.com/remote.php/dav/files/me/terminalmax/", user, davPassword)
val result = session.sync(store)                                 // SyncResult(outcome, content, warnings, localEditsPending)
result.warnings.forEach { /* show FirstUseTrust, StaleRemoteIgnored, ForkSuspected, KeyEpochChainUnverified, ... */ }
session.content                                                  // StateFlow<VaultContent>
session.keyEpoch                                                 // StateFlow<Long>: re-export the unlock secret when it changes
session.fingerprint()                                            // 6 groups of 4 hex characters, compare across devices

// A second device: preview first, nothing is written or uploaded until confirm().
val preview = VaultSession.join(dir2, store, password)           // downloads and decrypts
show(preview.fingerprint, preview.keyEpoch, preview.revision, preview.recordCounts)
val second = preview.confirm()                                   // or preview.close() to abandon

val changed = session.changePassword(old, new, remote = store)   // PasswordChangeResult(sync, imported, rekeyed)

val unlock = session.exportLocalUnlockSecret()                   // the data key itself: platform secure storage only
VaultSession.openWithLocalUnlockSecret(dir, unlock)              // KeyEpochMismatch after any password change
session.close()                                                  // zeroes the key, releases the directory
```

### One session per directory

`create`, `open`, `join`, `importBackup` and `salvage` take an OS-level `FileChannel` lock on
`terminalmax-sync-state.bin.lock` for the session's lifetime (a `JoinPreview` holds it until `confirm()`/`close()`). A
second open of the same directory, from another process or the same one, fails at once with
`VaultSessionException.DirectoryInUse`. Two sessions on one directory used to overwrite each other's edits; now the
second one cannot start. `close()` releases the lock (if a sync is running, as soon as it ends).

### Edits, sync and the network

`edit` takes only a short in-process lock on the state and never waits for the network. `sync` and `changePassword`
(serialised against each other) run the network I/O on a **snapshot**, outside every lock; when the exchange is done,
the result is committed together with the new sync state by **joining** it with whatever was edited meanwhile.
`SyncResult.localEditsPending` says so: the edits are in `content` and local state and go out with the next sync.
No edit is ever lost or blocked by a slow server.

### Persistence

`FileLocalStateStore(dir)` keeps `terminalmax-sync-state.bin` (`"TMXS"`, version, SHA-256, JSON). It holds, per vault
id: the sealed **local vault file** (ciphertext), the **base** file used for merging (ciphertext), the highest content
revision and key epoch, up to 64 file digests, an unpublished **pending rotation** (see below) and the persisted
key-epoch warning; per server: the probe result with its time (there is no ETag in the state); and the device id.
Everything that must stay consistent is written in a single replace: temp file, `fsync`, then the current file is
renamed to `terminalmax-sync-state.bin.prev` and the temp file renamed into place (atomic move; on Windows the move
is retried a few times and falls back to a plain replace, which the `.prev` copy makes safe), then a directory
`fsync`. A crash leaves the old state or the new one, and between the two renames `.prev` alone, which `load` then
uses. On macOS `fsync` is not `F_FULLFSYNC`: a power loss (not a crash) can lose the last write there.
`exclusive` is a short in-process mutex per path; it is not a file lock and nothing in it waits for the network.

**A damaged state file** is never replaced by an empty one and never silently by the previous copy:
`VaultSession.open` fails with `VaultSessionException.StateUnreadable` and `sync` with `LocalStateUnavailable`. The
recovery is `VaultSession.salvage(dir, password)` (below), which deletes and changes nothing.

`FileLocalStateStore.reset()` is a different, explicit action: it switches rollback protection off for a fresh start
by forgetting the floors, the merge base, the digests and the probe results. It **keeps** the sealed local vault, an
unpublished password change and the device id, so it never deletes vault content or unsynced edits. A state it
cannot read makes it throw unless `moveUnreadableAside = true`, which renames the damaged files to
`.unreadable-<time>` (never deletes them). The first sync after a reset is trust-on-first-use again
(`FirstUseTrust`).

The lower-level `SyncEngine` and `OpenVaultCodecHooks` remain building blocks covered by their own tests, but
nothing else should hold a key or a state file next to a session.

## Error model

| Call | How it fails |
|---|---|
| `VaultSession.create/open/join/importBackup/salvage` | throws: `VaultSessionException` (`DirectoryInUse`, `StateUnreadable`, `NoVault`, `AmbiguousDirectory`, `DirectoryHoldsVault`, `RemoteHasNoVault`, `ConfirmationRequired`), `VaultException` (`BadPasswordOrCorrupt`, `KdfCostTooHigh`, `KeyEpochMismatch`, ...), `LocalStateException`, `RemoteIoException` / `RemoteAuthException` for `join` |
| `edit` | throws (`InvalidContent` for content that breaks the rules; whatever the block throws; nothing changes) |
| `sync` | **never throws** for network, server or file problems: returns `SyncResult` with `SyncOutcome.Failed(reason)` |
| `changePassword` | throws for the arguments (`BadPasswordOrCorrupt` for a wrong `old`, `KdfCostTooHigh` for a `kdf` above the session's ceiling, `IllegalStateException` for a synced vault without a `remote`); a failed transaction is a `Failed` outcome inside `PasswordChangeResult.sync` |
| `replaceRemoteWithLocal` | throws `ConfirmationRequired` without `confirm = true`, `BadPasswordOrCorrupt` for a wrong password; otherwise `ReplaceRemoteResult` |
| `exportBackup`, `acknowledgeKeyEpochWarning` | throw `IllegalStateException` on a closed session only |

## Algorithm

1. **Probe** the server (result cached per server for 7 days, bound to the normalised URL plus user name, repeated
   after any precondition anomaly or with `SyncOptions.reprobe`). With a scratch file `terminalmax.probe-<16 hex>` it
   checks: a bogus `If-Match` is rejected (412); the **correct** ETag (taken from a GET, the same source the engine
   uses) is accepted; `If-None-Match: *` protects an existing file; the ETag changes when same-size content is
   replaced; a DELETE with a bogus `If-Match` deletes nothing; PUT responses carry an ETag; the ETags are strong,
   quoted, header-safe and at most 256 characters. Stale probe files left by a crashed probe are swept
   (Depth-1 PROPFIND, only names of exactly the scratch-file shape). The vault file is never touched by the probe.
2. **Read** the remote file and decrypt it with the data key. The authenticated key epoch and the content revision
   are compared with the **floors** this device remembers (highest ever seen, also taken from the stored base).
   * Lower key epoch: `RollbackDetected`, never overridable. Lower content revision: `RollbackDetected`,
     overridable with `SyncOptions.allowRollback`; the merge below still never lets an older record win.
   * A content revision more than `MAX_REVISION_JUMP` (2^20) above the floor is `SuspiciousRevisionJump` and is not
     merged (a hostile writer could otherwise make the vault un-editable); the user can accept it with
     `SyncOptions.acceptRevisionJump`, reported as `RevisionJumpAccepted`. A revision within `REVISION_HEADROOM`
     (2^32) of the maximum is never accepted.
   * **The header is immutable within a key epoch.** A file of the held epoch whose header differs from the held
     one (apart from the write salt) is `HeaderMismatchSameEpoch`: it is refused, not adopted, merged or
     overwritten. A file of the held epoch under another key (`KeyMismatchSameEpoch` underneath) and a file of a
     higher key epoch are both `ReopenRequired`: call `sync` again with the master password (`reopenPassword`). The
     new file is then checked against this device's old key with the epoch chain; a link that does not verify, and
     every same-epoch competitor, is reported with `SyncWarning.KeyEpochChainUnverified` or
     `ConcurrentRekeyAdopted`; a password that also opens the slot this device held before is
     `PasswordUnchangedByRekey`. The password is what authorises a new epoch; the chain only orders epochs.
3. **Merge** local, remote and the stored base. The merge keeps the highest version of every record. A remote that
   offers older versions that this device provably saw before (they are in the base or its history) is reported as
   `SyncWarning.StaleRemoteIgnored` and the newer versions are uploaded again; an older version it cannot prove it
   saw (including two devices that wrote the same revision) is a conflict, not a replay, and is kept in history. A
   different file than one seen before at the same revision is `SyncWarning.ForkSuspected`. The very first sync of
   an existing remote is `SyncWarning.FirstUseTrust`.
4. **Upload** only when the merge differs from the remote (`changedRemotely`), or for a staged password change. When
   the server honours preconditions (`supportsConditionalWrites`) the PUT carries `If-Match: <strong etag>`.
   Otherwise the whole read-merge-write runs under the lock lease (below). The uploaded revision is never at or below
   the floor.
5. **Read back** the file after every PUT; it must be byte-for-byte what was written, otherwise a concurrent writer got
   in between: nothing is recorded, the cached probe is dropped (conditional protocol), and the loop restarts (at most
   5 attempts, jittered backoff). Only then are the new base (as ciphertext), the floors, the file digest (at most
   64 per vault) saved, in one state write, joined with the edits made meanwhile.
6. **Remote file missing** although this device has synced the vault before: `Failed(RemoteMissing)` and nothing
   is uploaded. With `SyncOptions.recreateRemote` the device publishes its copy again, at a revision above the floor,
   with a `RemoteRecreated` warning.

**Warnings are sticky.** The chain warning of an adopted re-key (`KeyEpochChainUnverified`, `ConcurrentRekeyAdopted`)
is part of the persisted state. Every `SyncResult`, successful or failed, repeats it across retries and restarts until
the user calls `VaultSession.acknowledgeKeyEpochWarning()`. A *verified* chain only means "made by a holder of the
previous key", and that includes a stolen local unlock secret: do not present "no warning" as "trusted".

### Password change as one transaction

`VaultSession.changePassword(old, new, remote)` replaces the data key, which is why it is a sync transaction and not a
local edit:

1. verify `old`, then run a normal sync, so everything written at the old key epoch is imported. The result's
   `imported` lists those records (id, type, device id, revision): **show it to the user**, a device you are about to
   revoke may have written some of it. A password change carries them into the new epoch;
2. derive the new key and header in memory (a *staged* change); nothing local changes yet;
3. **write the sealed new-epoch local file durably as the state's pending rotation** (so no crash can leave a state
   that neither password opens);
4. upload the re-keyed file only if the remote file is still exactly what step 1 left (`If-Match`, or the lock lease
   on servers without preconditions). Another device having changed the vault meanwhile gives
   `RemoteChangedDuringRotation` or `HeaderChangedRemotely`; the pending rotation is dropped, nothing was changed,
   repeat the call;
5. read the upload back; **only then** commit the new key, the local file and the floors in one state write, which
   also clears the pending rotation.

**Crash points** (each is a test):

| Crash | State on restart | What happens |
|---|---|---|
| before step 3 | nothing changed | the old password works |
| after 3, upload did not land | committed file at the old epoch, pending file at the new one | the **old** password opens the committed file and the next `sync` discards the pending change (the server is at the old epoch). The **new** password opens the pending file; its `sync` fails with `PendingRotationUnpublished`, and the options are to open with the old password or to `replaceRemoteWithLocal` |
| upload landed, not yet recorded | as above, server at the new epoch | the old password opens the old file; `sync` gives `ReopenRequired`, and with the new password it adopts the epoch and clears the pending change. The new password opens the pending file; `sync` sees that the server holds it and clears it |
| after the state write, before the in-memory commit | new file is the local one | open with the new password |

A residual: an edit made in the few seconds between step 3 and step 5 is saved under the old key (the pending file was
sealed before it). If the process dies exactly there, that edit is in the committed old-epoch file only: opening
with the old password still has it,
while opening with the new password (the pending file) does not. Keep the old password until the change is
confirmed on every device.

Other devices follow with `ReopenRequired` and the password. **Revoking a device takes two actions: change the vault
password and change the WebDAV credential.** The password change protects what is written after it by devices that
have seen the new epoch; a device still at the old epoch can keep writing old-epoch files (only devices that have
seen the new epoch refuse them), cannot be made to forget what it read, and a holder of the old key can mint a linked
next epoch for devices that have not seen the real one (they then need a password for it). Changing the WebDAV
credential is what stops a revoked device from reading or writing the share at all.

Two devices that change the password at the same time cannot both succeed: step 4 uploads only if the remote is
still what that device last synced. The loser gets a failure, nothing changes on it, and it repeats the change on
top of the winner after a sync with the new password.

### Lock lease

Used only when the server cannot make the vault upload atomic. `terminalmax.lock` holds the device id, a random
token and an expiry. Its lease is 10 minutes (at least three times the HTTP call timeout) and is renewed before the
vault upload when less than 150 seconds remain. A lock is judged on the **server's** clock (the `Date` header), with
30 seconds of grace (5 minutes when the server sends no `Date` and only the local clock is available), so clock
skew between devices does not break a live lock; an expiry further than twice the lease away is clamped. A malformed
lock or one left by this very device counts as stale. A stale lock is deleted conditionally on the ETag that was read
when the server supports conditional deletes, so a lock that was replaced meanwhile survives; ownership of a new lock
is verified by reading it back; release deletes the lock only when it still carries our token. The residual race
(see below) is documented, not eliminated.

## Recovery actions

Every failure has a documented action. None of them runs automatically: each is a user decision, and each says what
it costs.

| Situation (`FailureReason`) | Action | Cost |
|---|---|---|
| `RollbackDetected` (lower content revision) | `SyncOptions.allowRollback`: accept the older file; the merge keeps every newer local record and reports `StaleRemoteIgnored` | none for records; a rollback of the key epoch is never overridable |
| `SuspiciousRevisionJump` | `SyncOptions.acceptRevisionJump`: accept a far-above-floor revision (reported as `RevisionJumpAccepted`); a revision at the limit is never accepted | the vault's revision counter jumps (it still has room above) |
| `RemoteMissing` | `SyncOptions.recreateRemote` (publishes this copy at a revision above the floor), or `replaceRemoteWithLocal` | what other devices wrote and this one never pulled is not on the server any more |
| `HeaderMismatchSameEpoch` (a file of the held epoch with another header: a substituted slot, or a hostile writer) | `replaceRemoteWithLocal(remote, password, confirm = true)` | see below |
| `BadPasswordOrCorrupt` on a same-epoch or higher-epoch remote that the password cannot open (a competing or hostile epoch) | `replaceRemoteWithLocal` | see below |
| `RemoteMissing`, `InvalidRemoteFile`, `IntegrityFailure`, `PendingRotationUnpublished` | `replaceRemoteWithLocal` | see below |
| `LocalStateUnavailable` / `StateUnreadable` | `VaultSession.salvage(dir, password)`, then `importBackup` into a fresh directory; `FileLocalStateStore.reset(moveUnreadableAside = true)` for a fresh start | floors of a salvaged state may be one step older; the first sync is trust-on-first-use |
| any | `exportBackup()` and `VaultSession.importBackup(dir, bytes, password)` | the backup is exactly as safe as the vault file on the server |

* **`replaceRemoteWithLocal(remote, password, confirm = true)`** never runs by itself (`confirm` must be true, the
  password is needed because replacing is a rotation). It first makes a final attempt to pull; if that works, nothing
  is replaced. Otherwise it uploads this device's vault as a **new key epoch above anything on the server** (a
  rotation with the password, so the epoch chain starts from this device's key), conditional on the remote being
  still the file it just looked at, reads it back and reports `SyncWarning.RemoteReplaced`. Other devices open it
  with the password (`ReopenRequired`), and they see an unverified chain unless they were exactly one epoch behind.
  **Whatever was on the server is gone from the share**, including anything other devices wrote and this device
  never pulled (they may still hold it locally: let them sync, or export a backup first). If the cause was a
  hostile writer, change the WebDAV credential as well.
* **`exportBackup()`** returns the sealed local vault (no more than the server holds). It works in every state,
  including when sync is stuck.
* **`salvage(dir, password)`** reads the state file leniently (a failed checksum does not stop it) and the rolling
  `.prev` copy, newest first, and tries the password on the local vault and the pending rotation of each. It returns
  `Recovered(source, revision, recordCount, fromPendingRotation, sealedVault)` or `NothingRecovered(triedSources)`.
  It deletes and changes nothing. Give `sealedVault` to `importBackup` in a fresh directory to continue.
* **`acknowledgeKeyEpochWarning()`** only after the user has seen the warning.

## What a hostile WebDAV server (or anyone with write access to the share) can and cannot do

Assume the server, or anyone with write access to the share, is fully malicious.

**It cannot**
* read your hosts, identities, private keys or any other record, or learn their names;
* forge or alter a file so that it opens: every change to the file or its header makes decryption fail;
* make a device **lose a newer edit** by serving an older authentic file (a replay, or a pre-edit file shown to a
  second device). On a device that has synced before, that is refused as `RollbackDetected`; even when you
  explicitly allow it, the merge keeps the newer record and reports a `StaleRemoteIgnored` warning, and the next
  upload puts the newer data back;
* bring back an **old password** by replaying an old file: the device has remembered the highest key epoch and
  refuses lower ones. This holds for devices that have already synced the vault and a persistent state store; a
  device that is behind on epochs is only protected once it has seen the newer epoch (see *It can still*);
* silently **delete the vault**: a missing remote file is reported as `RemoteMissing` and nothing is uploaded until
  you choose to re-create or replace it; a re-created file is always above the revision already seen;
* make `sync` crash or hang with hostile headers or XML: ETags that are not strong, quoted visible ASCII of at most
  256 characters are never sent back, a malformed header becomes an ordinary failure, redirects to another host or
  port are refused before any credential leaves the device, responses are size-capped, and the XML scanner is linear
  time and never resolves entities;
* make a device spend **unbounded** memory or time on key derivation: a file with a slot above the limits or above
  the session's memory ceiling is rejected before the Argon2 call, the session's ceiling applies to open, to
  re-key adoption, to a password change and to a join, and an out-of-memory error inside the derivation is
  reported as `KdfCostTooHigh`;
* redirect your credentials to another host: credentials go only to the configured origin, and HTTP to a non-local
  host is refused unless explicitly allowed.

**It can still**
* **Show a fresh device an old authentic file.** A device that has never synced the vault has nothing to compare
  with and accepts what it gets (trust on first use). Use `VaultSession.join`: its preview carries the fingerprint
  (`SHA-256(vaultId | keyEpoch | keyCommit)`, 6 groups of 4 hex characters) to compare with a device that already
  has the vault, before anything is written. After the first sync the floors protect the device. The floors live in
  the state store: without a persistent one (or after `reset()` or reinstalling) the protection starts again.
* **Serve a device an older key epoch.** A device that last saw epoch *n* and is offered a file at *n* that predates a
  password change cannot know a change happened until it sees the newer epoch; the server can keep it on the old
  epoch indefinitely, and such a device keeps writing old-epoch files. This is why revocation is complete only once
  every device has synced the new epoch.
* **Let a holder of a device's local unlock secret and write access put a second header into the file.** The data
  key lets its holder re-seal a file of that epoch with any header, including a password slot of its own. The format
  cannot stop that; every device that holds the same key **refuses** such a file (`HeaderMismatchSameEpoch`) and
  never adopts or re-seals it, so the substituted slot never spreads. That is a refusal of service (the share is
  stuck until `replaceRemoteWithLocal`), not a compromise of the data. To get rid of the secret's holder, change the
  vault password and the WebDAV credential.
* **Put up to two password guesses in front of the user.** Whoever can write the share can offer a re-keyed file
  that opens with a password they chose, or with the user's old one, and the device then asks for "the password". The
  device warns when a typed password also opens the slot it held (`PasswordUnchangedByRekey`) and when the chain
  does not verify, and repeats the warning until it is acknowledged; the user should type the password only after
  checking with another device that the vault was re-keyed.
* **Mint an unopenable epoch that blocks every device and the password change.** A file at a higher epoch that the
  password does not open is `BadPasswordOrCorrupt` on every device, for ever, until it is replaced
  (`replaceRemoteWithLocal`). That is denial of service.
* **Withhold updates or refuse service.** It can hide new versions, fail every request, answer slowly, or delete the
  lock and vault files. That cannot be told apart from an outage and is not prevented, only reported as an error.
  A device then keeps working locally and syncs when the server behaves.
* **Learn metadata**: file size (which grows with the number of records), the time and frequency of updates, which
  device writes when (device ids are inside the encrypted file, but the IP addresses are visible), the KDF
  parameters and the key epoch.
* **Fork the history**: serve different files to different devices at the same revision. Devices report
  `ForkSuspected` when they have seen both files; the merge keeps everything. Without a second device that has seen
  the other file, a fork is invisible.
* **Cheat a probe it can recognise.** The probe measures behaviour on a scratch file named
  `terminalmax.probe-...`; a server could behave differently for that name than for the vault file. The read-back after
  every upload and the monotone merge limit the damage to "delayed, not lost". The probe result is also cached, so a
  server that changes its behaviour later is noticed on the next read-back mismatch or after 7 days.
* **Guess your password offline** from a copy of the file. Argon2id cost and a strong password are the defence.
* **Win the residual lock race.** On a server that ignores preconditions, two devices can both believe they hold the
  lease for a moment; the read-back and the merge mean no record is lost, but one device may have to repeat its
  attempt. Locks are protected only against honest clients.

## Not done yet

* Background scheduling and conflict-resolution UI, and a user interface for the warnings and the recovery actions.
* Secure storage of the local unlock secret (Android Keystore / DPAPI / macOS Keychain): the session only produces
  and consumes the raw bytes.
* A list of the records changed by an ordinary sync (only `changePassword` reports `imported`); a guard against mass
  deletion by a remote.
* `VaultCodec.migrateToNewVault` (the recovery from an exhausted revision counter) is not exposed by the session.
* Tombstone garbage collection.
* Cancelling an in-flight HTTP call promptly (blocking OkHttp calls run on `Dispatchers.IO` and end by timeout), and
  streaming of large responses (a plain 8 MiB cap is applied).
* The residual lock race on servers that ignore preconditions is documented, not removed.
