# :core:sync

WebDAV synchronisation of the encrypted vault file produced by `:core:vault` (format version 2).

* `commonMain`: `RemoteStore` (single vault file plus a lock file), `ServerCapabilities`, `DeleteResult`,
  `SyncEngine`, `SyncOutcome` / `SyncResult` / `SyncWarning` / `SyncOptions` / `FailureReason`, `LocalStateStore`
  with `LocalSyncState` / `VaultSyncState` / `ServerSyncState`, `VaultCodecHooks` (the engine's view of encryption,
  including `StagedHeaderChange`), `isStrongEtag` / `usableEtag`. The in-memory state store is `internal` (tests).
* `jvmCommonMain` (Android + desktop): **`VaultSession`** (the facade apps use), `WebDavStore` (OkHttp 5),
  `PropfindParser`, `FileLocalStateStore`, and `OpenVaultCodecHooks` (internal; it holds the data key).

## Use `VaultSession`

`VaultSession` is the one thing an app should hold. It owns the local vault file, the sync state and the data key,
and runs `edit`, `sync` and `changePassword` under one mutex, so an edit can never be overwritten by a sync that is
already running and a sync always starts from the latest edit.

```kotlin
val dir = File(context.filesDir, "vault")                       // one directory per local vault
val session = VaultSession.create(dir, password)                 // or VaultSession.open(dir, password)
session.edit { it.upsertHost(HostPayload("router", "192.0.2.1", 22, "admin")) }   // committed to disk, then published
val store = WebDavStore("https://dav.example.com/remote.php/dav/files/me/terminalmax/", user, davPassword)
val result = session.sync(store)                                 // SyncResult(outcome, content, warnings); never throws
result.warnings.forEach { /* show FirstUseTrust, StaleRemoteIgnored, ForkSuspected, KeyEpochChainUnverified, ... */ }
session.content                                                  // StateFlow<VaultContent>

session.changePassword(old, new, remote = store)                 // one sync transaction, see below

val unlock = session.exportLocalUnlockSecret()                   // the data key itself: platform secure storage only
VaultSession.openWithLocalUnlockSecret(dir, unlock)              // KeyEpochMismatch after any password change
session.close()                                                  // zeroes the key
```

**Persistence is one file.** `FileLocalStateStore(dir)` keeps `terminalmax-sync-state.bin` (`"TMXS"`, version,
SHA-256, JSON). It holds, per vault id: the sealed **local vault file** (ciphertext), the **base** file used for
merging (ciphertext), the highest content revision, key epoch and header revision, and up to 64 file digests; per
server: the last ETag and the probe result with its time; and the device id. Everything that must stay consistent
(the local file and the floors) is written in a single replace: temp file, `fsync`, atomic rename over the state file,
directory `fsync`, so a crash leaves the old state or the new one and never a vault file that is out of step with its
floors. A damaged or unreadable state file is **never** replaced by an empty one: `sync` fails with
`LocalStateUnavailable` and `FileLocalStateStore.reset()` is the explicit way out (it switches rollback protection off
for a fresh start). `exclusive` serialises users of the same directory with a mutex plus an OS file lock on
`terminalmax-sync-state.bin.lock`; a second process is kept out during each operation but its edits are not merged
into a running session.

The lower-level `SyncEngine` and `OpenVaultCodecHooks` remain public/internal building blocks and are covered by their
own tests, but nothing else should hold a key or a state file next to a session.

## Algorithm

1. **Probe** the server (result cached per server for 7 days, bound to the normalised URL plus user name, repeated
   after any precondition anomaly or with `SyncOptions.reprobe`). With a scratch file `terminalmax.probe-<16 hex>` it
   checks: a bogus `If-Match` is rejected (412); the **correct** ETag (taken from a GET, the same source the engine
   uses) is accepted; `If-None-Match: *` protects an existing file; the ETag changes when same-size content is
   replaced; a DELETE with a bogus `If-Match` deletes nothing; PUT responses carry an ETag; the ETags are strong,
   quoted, header-safe and at most 256 characters. Stale probe files left by a crashed probe are swept
   (Depth-1 PROPFIND, only names of exactly the scratch-file shape). The vault file is never touched by the probe.
2. **Read** the remote file and decrypt it with the data key. The authenticated key epoch and header revision and
   the content revision are compared with the **floors** this device remembers (highest ever seen, also taken from
   the stored base). Lower key epoch or header revision: `RollbackDetected`, never overridable. Lower content
   revision: `RollbackDetected`, overridable with `SyncOptions.allowRollback`; the merge below still never lets an
   older record win. A content revision more than `MAX_REVISION_JUMP` (2^20) above the floor, or within
   `REVISION_HEADROOM` (2^32) of the maximum revision, is `SuspiciousRevisionJump` and is not merged (a hostile
   writer could otherwise make the vault un-editable). A newer key epoch: `ReopenRequired` (the vault key was rotated
   elsewhere): call `sync` again with the master password (`reopenPassword`). The new file is then checked against
   this device's old key with the epoch chain; a link that does not verify is reported as
   `SyncWarning.KeyEpochChainUnverified`, which tells the user that a device this one cannot verify re-keyed the
   vault (only someone who knows the password could have, since the new epoch opened with it).
3. **Merge** local, remote and the stored base. The merge keeps the highest version of every record. A remote that
   offers older versions that this device provably saw before (they are in the base or its history) is reported as
   `SyncWarning.StaleRemoteIgnored` and the newer versions are uploaded again; an older version it cannot prove it
   saw (including two devices that wrote the same revision) is a conflict, not a replay, and is kept in history. A different file than one seen before at the same revision is
   `SyncWarning.ForkSuspected`. The very first sync of an existing remote is `SyncWarning.FirstUseTrust`.
4. **Upload** when the merge differs from the remote, or when this device holds a newer key epoch or slot set. When
   the server honours preconditions (`supportsConditionalWrites`) the PUT carries `If-Match: <strong etag>`.
   Otherwise the whole read-merge-write runs under the lock lease (below). The uploaded revision is never at or below
   the floor and the header written is the newest known one.
5. **Read back** the file after every PUT; it must be byte-for-byte what was written, otherwise a concurrent writer got
   in between: nothing is recorded, the cached probe is dropped (conditional protocol), and the loop restarts (at most
   5 attempts, jittered backoff). Only then are the new base (as ciphertext), the floors, the file digest (at most
   64 per vault) and the ETag saved.
6. **Remote file missing** although this device has synced the vault before: `Failed(RemoteMissing)` and nothing
   is uploaded. With `SyncOptions.recreateRemote` the device publishes its copy again, at a revision above the floor,
   with a `RemoteRecreated` warning.

### Password change as one transaction

`VaultSession.changePassword(old, new, remote)` replaces the data key, which is why it is a sync transaction and not a
local edit:

1. verify `old`, then run a normal sync, so everything written at the old key epoch is imported (and reported);
2. derive the new key and header in memory (a *staged* change); nothing local changes yet;
3. upload the re-keyed file only if the remote file is still exactly what step 1 left (`If-Match`, or the lock lease
   on servers without preconditions). Another device having changed the vault meanwhile gives
   `RemoteChangedDuringRotation` or `HeaderChangedRemotely`; nothing was changed, repeat the call;
4. read the upload back; **only then** commit the new key, the local file and the floors in one state write.

A crash or failure before step 4 leaves the old password and epoch untouched, and the remote at worst already holds
the new epoch (which this device then adopts through `ReopenRequired` plus its password). Other devices follow with
`ReopenRequired`. Revocation of a device takes effect once every remaining device has synced at the new epoch; until
then a device still at the old epoch can write old-epoch files, and only devices that have seen the new epoch refuse
them. It cannot recall what a device already read.

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

## What a hostile WebDAV server can and cannot do

Assume the server, or anyone with write access to the share, is fully malicious. This is what that means for you
after the fixes in this version.

**It cannot**
* read your hosts, identities, private keys or any other record, or learn their names;
* forge or alter a file so that it opens: every change to the file or its header makes decryption fail;
* make a device **lose a newer edit** by serving an older authentic file (a replay, or a pre-edit file shown to a
  second device). On a device that has synced before, that is refused as `RollbackDetected`; even when you
  explicitly allow it, the merge keeps the newer record and reports a `StaleRemoteIgnored` warning, and the next
  upload puts the newer data back;
* bring back a **removed key slot or an old password** by replaying an old header: the device has remembered the
  highest key epoch and slot-set revision, refuses lower ones, and never uploads one. This holds for devices that have
  already synced the vault and a persistent state store; a device that is behind on epochs is only protected once it
  has seen the newer epoch (see *It can still*);
* silently **delete the vault**: a missing remote file is reported as `RemoteMissing` and nothing is uploaded until
  you choose to re-create it; a re-created file is always above the revision already seen;
* make `sync` crash or hang with hostile headers or XML: ETags that are not strong, quoted visible ASCII of at most
  256 characters are never sent back, a malformed header becomes an ordinary failure, redirects to another host or
  port are refused before any credential leaves the device, responses are size-capped, and the XML scanner is linear
  time and never resolves entities;
* make a device spend unbounded memory or time on key derivation: a file with too many or too expensive password slots
  is rejected before any Argon2 call;
* redirect your credentials to another host: credentials go only to the configured origin, and HTTP to a non-local
  host is refused unless explicitly allowed.

**It can still**
* **Show a fresh device an old authentic file.** A device that has never synced the vault has nothing to compare
  with and accepts what it gets (trust on first use). It reports `FirstUseTrust` with the revision, so compare it
  with what another device shows. After the first sync the floors protect it. The floors live in the state store:
  without a persistent one (or after `reset()` or reinstalling) the protection starts again from nothing.
* **Serve a device an older key epoch.** A device that last saw epoch *n* and is offered a file at *n* that predates a
  password change has no way to know a change happened until it sees the newer epoch; the server can keep it on the
  old epoch indefinitely, and such a device keeps writing old-epoch files. This is the same withholding attack as
  below and is why revocation is only complete once every device has synced the new epoch.
* **Withhold updates or refuse service.** It can hide new versions, fail every request, answer slowly, or delete the
  lock and vault files. That cannot be told apart from an outage and is not prevented, only reported as an error.
  A device then keeps working locally and syncs when the server behaves.
* **Learn metadata**: file size (which grows with the number of records), the time and frequency of updates, which
  device writes when (device ids are inside the encrypted file, but the IP addresses are visible), the number and type
  of key slots, the key epoch and header revision, and the KDF parameters.
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

* Background scheduling and conflict-resolution UI.
* A user interface for the warnings and for choosing `allowRollback` / `recreateRemote` / `reset()`.
* Secure storage of the local unlock secret (Android Keystore / DPAPI / macOS Keychain): the session only produces
  and consumes the raw bytes.
* Tombstone garbage collection.
* Cancelling an in-flight HTTP call promptly (blocking OkHttp calls run on `Dispatchers.IO` and end by timeout), and
  streaming of large responses (a plain 8 MiB cap is applied).
* Merging concurrent key rotations by two devices (one of them has to re-open the vault).
* The residual lock race on servers that ignore preconditions is documented, not removed (see below).
* `VaultSession.changePassword` supports a vault with a single password slot; managing the second slot is done with
  `VaultCodec` directly.
