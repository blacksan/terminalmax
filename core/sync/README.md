# :core:sync

WebDAV synchronisation of the encrypted vault file produced by `:core:vault`.

* `commonMain`: `RemoteStore` (abstract single-file store with lock-file operations), `ServerCapabilities`,
  `SyncEngine`, `SyncOutcome` / `SyncResult` / `FailureReason`, `LocalStateStore` with an in-memory implementation,
  `VaultCodecHooks` (the engine's view of encryption).
* `jvmCommonMain` (Android + desktop): `WebDavStore` (OkHttp 5), `PropfindParser`, `OpenVaultCodecHooks`.

```kotlin
val store = WebDavStore("https://dav.example.com/remote.php/dav/files/me/terminalmax/", user, password)
val hooks = OpenVaultCodecHooks(openVault)
val engine = SyncEngine(store, hooks, InMemoryLocalStateStore(), deviceId, clock = ::systemClockMillis)
val result = engine.sync(localContent)        // SyncResult(outcome, content)
localContent = result.content
```

## Algorithm

1. Probe the server once (cached in the local state): using a scratch file `terminalmax.probe-<random>` it checks
   whether a bogus `If-Match` is rejected (412), whether `If-None-Match: *` protects an existing file, whether the
   ETag changes when same-size content is replaced, whether PUT responses carry an ETag, and whether ETags are
   strong. The scratch file is deleted afterwards.
2. Read the remote file. If it is absent, upload the local vault with `If-None-Match: *`.
3. Otherwise decrypt it, refuse it if its revision is lower than the highest ever seen for this vault (rollback;
   `SyncOptions.allowRollback` overrides), and three-way merge with the stored base.
4. If the merge differs from the remote, upload it. When the server honours preconditions reliably
   (`ServerCapabilities.supportsConditionalWrites`) the PUT carries `If-Match: <strong etag>`. Otherwise the whole
   read-merge-write runs under a lease in `terminalmax.lock` (device id, random token, expiry; 60 s lease; created
   with `If-None-Match: *` where supported and verified by reading it back; broken only if unreadable, ours, or older
   than twice the lease).
5. After every PUT the file is read back; it must be byte-for-byte what was written. If not, a concurrent writer got
   in between: nothing is recorded and the loop restarts (at most 5 attempts, jittered backoff). Only then is the
   merged content stored as the new base.

HTTP 412 also restarts the loop. Weak ETags (`W/"..."`) are never sent in `If-Match`.

## Threat model

A malicious or compromised WebDAV server (or anyone with write access to the share) can delete the file, serve an
older version, or withhold updates. It cannot read vault contents or forge a file that decrypts. Deletion is
recoverable (the next sync re-uploads), rollback is detected on devices that have seen a newer revision, withholding
is not detectable. Metadata leaked: file size, timing and frequency of updates, the number of key slots.

`WebDavStore` refuses plain HTTP to non-local hosts (unless explicitly allowed), sends Basic credentials only to the
configured origin, never follows a redirect to another origin, caps response sizes, and extracts ETags with a scanner
that cannot resolve entities (documents with a DTD are rejected).

Limits of the lock fallback: the lease assumes roughly synchronised clocks and cooperating TerminalMax clients; a
non-cooperating writer on a server without precondition support can still overwrite between our read and write. The
read-back check detects overwrites after our write, not before it.

## Not done yet

* Background scheduling and conflict-resolution UI.
* File-backed `LocalStateStore` (state is lost on restart with the in-memory store; a lost base degrades to a
  two-way merge, a lost highest-revision weakens rollback detection).
* Secure storage of the device key (Android Keystore / DPAPI / macOS Keychain) used for device slots.
* Tombstone garbage collection.
* Cancelling an in-flight HTTP call promptly (blocking OkHttp calls run on `Dispatchers.IO` and end by timeout).
