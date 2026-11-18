// SPDX-License-Identifier: GPL-3.0-or-later
@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package org.terminalmax.core.sync

import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.ByteBuffer
import java.nio.channels.OverlappingFileLockException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.FileAttribute
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.encoding.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** Where a salvaged state came from (see [FileLocalStateStore.salvageCandidates]). */
enum class SalvageSource { Current, CurrentIgnoringChecksum, Previous, PreviousIgnoringChecksum }

/**
 * File-backed [LocalStateStore]: the rollback floors, the merge base (the encrypted file as last synced), the
 * file digests used for fork detection, and the per-server probe result survive restarts, so rollback protection
 * does not reset every time the OS kills the app.
 *
 * Layout: one state file, `<directory>/<fileName>`. It holds `"TMXS" | u8 version | SHA-256(payload) | payload`
 * where the payload is JSON: the floors, digests and probe results, the base file, and (when a `VaultSession` owns the
 * directory) the sealed local vault file, an unpublished password change and the device id. **That single file is the
 * manifest**: it is replaced atomically, so the local vault and the sync state cannot diverge after a crash. It
 * contains no plaintext secrets (the vault files are ciphertext), but it should still live in the app's private
 * storage; whoever can rewrite it can lower the floors or substitute an older local vault.
 *
 * **Durability.** [save] writes `<fileName>.tmp` completely and forces it to disk (`fsync`); then it renames the
 * current file to `<fileName>.prev` (replacing the previous copy), renames the temp file over the state file and
 * forces the directory. So there is always a rolling previous copy of the state. A crash at any point leaves the
 * old state or the new one: between the two renames only `.prev` exists, and [load] then uses it (it is the last
 * state that was ever acknowledged). Renames use an atomic move and, where the file system cannot do that or
 * another process (an antivirus scanner, an indexer, a sync client) briefly holds the target open on Windows,
 * retry a few times and finally fall back to a plain replace; the previous copy makes that fallback safe. Note that
 * on macOS `fsync` does not force the drive cache (`F_FULLFSYNC`), so a power loss can still cost the last save.
 *
 * **Damage.** The checksum catches torn or damaged files: [load] then throws [LocalStateException] and everything
 * above it fails closed, because silently starting from an empty state would switch rollback protection off and
 * make the only copy of unsynced edits unreachable. The damaged file is never replaced or deleted by the store.
 * [salvageCandidates] reads the damaged file leniently and the previous copy so that the vault content can still be
 * recovered with the password (`VaultSession.salvage`). [reset] never deletes the vault content.
 *
 * **Concurrency.** [exclusive] is a per-path in-process mutex around one load-modify-save; it holds no file lock and
 * must not contain network I/O. Exclusion from other processes (and from a second session in this process) is
 * [lockDirectory], an OS-level lock held for the lifetime of a `VaultSession`. Without it a state store has no
 * protection against another process.
 *
 * **Permissions.** On POSIX file systems the directory is created `0700` and every file the store creates (state, temp,
 * previous copy, lock) `0600`, set at creation through `java.nio.file` attributes (existing files are tightened
 * best-effort when the directory is locked; an existing directory is never chmod-ed). On Windows nothing is set: the
 * files inherit the ACL of the profile folder they are in, which already restricts them to the user (and
 * administrators). What is stored in the clear is documented in the sync README (vault id, revisions, key epoch, file
 * digests, device id; the probe results per server).
 *
 * @param directory a directory supplied by the app (for example `context.filesDir` + "/sync"); created if missing
 */
class FileLocalStateStore(directory: File, fileName: String = DEFAULT_FILE_NAME) : LocalStateStore {
    private val dir: File = directory.absoluteFile
    private val stateFile = File(dir, fileName)
    private val tempFile = File(dir, "$fileName.tmp")
    private val prevFile = File(dir, "$fileName.prev")
    private val lockFile = File(dir, "$fileName.lock")

    @Volatile
    private var cached: LocalSyncState? = null

    /** Size and modification time of the state file when it was last read or written (to notice foreign changes). */
    @Volatile
    private var stamp: Pair<Long, Long>? = null

    /** True when the last [load] came from the rolling previous copy because the state file itself was missing. */
    @Volatile
    var loadedFromPrevious: Boolean = false
        private set

    /** Test hook: runs after the temp file is durable and before anything is renamed (to simulate a crash there). */
    internal var beforeRenameHook: (() -> Unit)? = null

    /** Test hook: runs between "state -> .prev" and "temp -> state" (the window in which only `.prev` exists). */
    internal var betweenRenamesHook: (() -> Unit)? = null

    override suspend fun load(): LocalSyncState {
        cached?.let { return it }
        val loaded = withContext(Dispatchers.IO) { readFromDisk() }
        cached = loaded
        return loaded
    }

    override suspend fun save(state: LocalSyncState) {
        withContext(Dispatchers.IO) { writeToDisk(state) }
        cached = state
    }

    override suspend fun <T> exclusive(block: suspend () -> T): T {
        val mutex = mutexes.computeIfAbsent(pathKey()) { Mutex() }
        return mutex.withLock {
            // Another store object on the same file (a test, a tool) may have written since this one looked.
            if (stamp != statFile()) cached = null
            block()
        }
    }

    private fun pathKey(): String = try {
        stateFile.canonicalPath
    } catch (e: IOException) {
        stateFile.absolutePath
    }

    private fun statFile(): Pair<Long, Long>? = if (stateFile.exists()) stateFile.length() to stateFile.lastModified() else null

    /**
     * Takes the OS-level lock on this directory's state **without waiting** and returns the handle that holds it. A
     * `VaultSession` holds it from open to close, so two sessions (two windows, an app and a background service,
     * two instances in one process) can never edit the same vault concurrently and lose each other's edits.
     *
     * @throws VaultSessionException.DirectoryInUse when another session, process or store object holds it
     * @throws LocalStateException when the lock file cannot be opened
     */
    fun lockDirectory(): DirectoryLock {
        // Process-wide registry first: a second open in this process is rejected BEFORE any channel on the lock file
        // is opened, because closing any descriptor of a file drops all of the process's POSIX locks on it.
        val key = lockKey()
        val token = Any()
        if (openDirectories.putIfAbsent(key, token) != null) throw VaultSessionException.DirectoryInUse(dir)
        var channel: FileChannel? = null
        try {
            ensureDirectory()
            tightenExisting()
            channel = FileChannel.open(
                lockFile.toPath(), setOf(StandardOpenOption.CREATE, StandardOpenOption.WRITE), *fileAttributes(),
            )
            val lock: FileLock? = try {
                channel.tryLock()
            } catch (e: OverlappingFileLockException) {
                null // cannot happen while the registry holds the entry, but never close a channel then
            }
            if (lock == null) {
                // Another process holds it; this process holds no lock on the file (registry), so closing is safe.
                runCatching { channel.close() }
                openDirectories.remove(key, token)
                throw VaultSessionException.DirectoryInUse(dir)
            }
            return DirectoryLock(channel, lock, key, token)
        } catch (e: VaultSessionException) {
            throw e
        } catch (e: LocalStateException) {
            openDirectories.remove(key, token)
            throw e
        } catch (e: IOException) {
            runCatching { channel?.close() }
            openDirectories.remove(key, token)
            throw LocalStateException("The sync state lock cannot be taken", e)
        }
    }

    private fun lockKey(): String = try {
        lockFile.canonicalPath
    } catch (e: IOException) {
        lockFile.absolutePath
    }

    private val posix: Boolean = try {
        dir.toPath().fileSystem.supportedFileAttributeViews().contains("posix")
    } catch (e: Exception) {
        false
    }

    private fun fileAttributes(): Array<FileAttribute<*>> =
        if (posix) arrayOf(PosixFilePermissions.asFileAttribute(OWNER_FILE)) else emptyArray()

    /** Creates the directory (`0700` on POSIX, set at creation); an existing directory is left as it is. */
    private fun ensureDirectory() {
        if (dir.isDirectory) return
        try {
            if (posix) {
                Files.createDirectories(dir.toPath(), PosixFilePermissions.asFileAttribute(OWNER_DIR))
            } else {
                dir.mkdirs()
            }
        } catch (e: FileAlreadyExistsException) {
            // A concurrent creator won.
        } catch (e: IOException) {
            throw LocalStateException("The sync state directory cannot be created", e)
        }
        if (!dir.isDirectory) throw LocalStateException("The sync state directory cannot be created")
    }

    /** Best effort: files of an older version of the store (created with the default umask) become owner-only. */
    private fun tightenExisting() {
        if (!posix) return
        for (f in listOf(stateFile, prevFile, lockFile, tempFile)) {
            if (f.exists()) {
                try {
                    Files.setPosixFilePermissions(f.toPath(), OWNER_FILE)
                } catch (e: Exception) {
                    // Not ours to change; the session works either way.
                }
            }
        }
    }

    /** The OS-level directory lock; closing it releases the lock (idempotent). */
    class DirectoryLock internal constructor(
        private val channel: FileChannel,
        private val lock: FileLock,
        private val key: String,
        private val token: Any,
    ) : AutoCloseable {
        @Volatile
        private var closed = false

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            try {
                lock.release()
            } catch (e: IOException) {
                // The lock goes away when the channel is closed.
            }
            try {
                channel.close()
            } catch (e: IOException) {
                // Nothing more to do.
            }
            openDirectories.remove(key, token)
        }
    }

    /**
     * The explicit way to start rollback protection from scratch (a user decision: it switches the floors off).
     * It **never deletes the vault**: the sealed local vault file, an unpublished password change and the device id
     * are kept; the merge base, the floors, the file digests and the probe results are forgotten. Takes the same
     * in-process mutex as [exclusive], so call it outside [exclusive], and without a `VaultSession` open on the
     * directory.
     *
     * A state file that cannot be read is not touched unless [moveUnreadableAside] is set: then it (and the
     * previous copy) is renamed to `<name>.unreadable-<time>` (never deleted, so `salvage` can still read it) and
     * the state starts empty. Without the flag the call throws [LocalStateException]; try `VaultSession.salvage`
     * first.
     */
    suspend fun reset(moveUnreadableAside: Boolean = false) {
        exclusive {
            withContext(Dispatchers.IO) {
                val current = try {
                    readFromDisk()
                } catch (e: LocalStateException) {
                    if (!moveUnreadableAside) {
                        throw LocalStateException(
                            "The state file is unreadable: salvage it first, or reset with moveUnreadableAside", e,
                        )
                    }
                    val suffix = ".unreadable-" + System.currentTimeMillis()
                    for (f in listOf(stateFile, prevFile)) {
                        if (f.exists()) Files.move(f.toPath(), File(f.path + suffix).toPath())
                    }
                    cached = LocalSyncState()
                    stamp = null
                    return@withContext
                }
                val kept = LocalSyncState(
                    vaults = current.vaults
                        .mapValues { (_, v) -> VaultSyncState(
                                localFile = v.localFile,
                                pendingLocalFile = v.pendingLocalFile,
                                pendingHoldsNewerEdits = v.pendingHoldsNewerEdits,
                                discardedPendingEpoch = v.discardedPendingEpoch,
                                chainWarning = v.chainWarning,
                            )
                        }
                        .filterValues { it.localFile != null || it.pendingLocalFile != null },
                    servers = emptyMap(),
                    deviceId = current.deviceId,
                )
                writeToDisk(kept)
                cached = kept
            }
        }
    }

    // ------------------------------------------------------------------ reading

    private fun readFromDisk(): LocalSyncState {
        if (!stateFile.exists()) {
            if (prevFile.exists()) {
                // Only the window between the two renames of a save (or a lost file) gets here: the previous copy is
                // the last state that was ever acknowledged, so it is used instead of starting empty.
                val state = readStrict(prevFile)
                loadedFromPrevious = true
                stamp = null
                return state
            }
            loadedFromPrevious = false
            stamp = null
            return LocalSyncState()
        }
        val state = readStrict(stateFile) // a damaged current file is never replaced silently by the previous copy
        loadedFromPrevious = false
        stamp = statFile()
        return state
    }

    private fun readStrict(file: File): LocalSyncState {
        try {
            if (file.length() > MAX_STATE_BYTES) throw LocalStateException("The sync state file is too large")
            val bytes = file.readBytes()
            val prefix = MAGIC.size + 1 + DIGEST_BYTES
            if (bytes.size < prefix || !bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) || bytes[MAGIC.size] != VERSION) {
                throw LocalStateException("The sync state file is not valid")
            }
            val digest = bytes.copyOfRange(MAGIC.size + 1, prefix)
            val payload = bytes.copyOfRange(prefix, bytes.size)
            if (!MessageDigest.isEqual(digest, MessageDigest.getInstance("SHA-256").digest(payload))) {
                throw LocalStateException("The sync state file failed its checksum")
            }
            return decode(payload.decodeToString())
        } catch (e: LocalStateException) {
            throw e
        } catch (e: Exception) {
            throw LocalStateException("The sync state file cannot be read", e)
        }
    }

    /** A state read for recovery. [checksumOk] is false for a file whose payload still decodes although its checksum fails. */
    class SalvagedState(val source: SalvageSource, val state: LocalSyncState, val checksumOk: Boolean)

    /**
     * Every state that can still be read from the state file and from the rolling previous copy, newest first, for
     * recovery. The checksum is **not** required (a file damaged outside the part that matters may still decode:
     * the vault inside is self-authenticating, so the checksum protects the floors, not the vault). Reads only;
     * nothing is changed, replaced or deleted.
     */
    fun salvageCandidates(): List<SalvagedState> {
        val out = ArrayList<SalvagedState>()
        for ((file, strictSource, lenientSource) in listOf(
            Triple(stateFile, SalvageSource.Current, SalvageSource.CurrentIgnoringChecksum),
            Triple(prevFile, SalvageSource.Previous, SalvageSource.PreviousIgnoringChecksum),
        )) {
            if (!file.exists()) continue
            val parsed = readLenient(file) ?: continue
            out += SalvagedState(if (parsed.second) strictSource else lenientSource, parsed.first, parsed.second)
        }
        return out
    }

    private fun readLenient(file: File): Pair<LocalSyncState, Boolean>? {
        try {
            if (file.length() > MAX_STATE_BYTES) return null
            val bytes = file.readBytes()
            val prefix = MAGIC.size + 1 + DIGEST_BYTES
            if (bytes.size < prefix || !bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) || bytes[MAGIC.size] != VERSION) return null
            val digest = bytes.copyOfRange(MAGIC.size + 1, prefix)
            val payload = bytes.copyOfRange(prefix, bytes.size)
            val ok = MessageDigest.isEqual(digest, MessageDigest.getInstance("SHA-256").digest(payload))
            return decode(payload.decodeToString()) to ok
        } catch (e: Exception) {
            return null
        }
    }

    private fun decode(text: String): LocalSyncState {
        val root = Json.parseToJsonElement(text).jsonObject
        val vaults = LinkedHashMap<String, VaultSyncState>()
        for ((id, element) in root.getValue("vaults").jsonObject) {
            val o = element.jsonObject
            val base = o["base"]?.jsonPrimitive?.content?.let { Base64.Default.decode(it) }
            val localFile = o["local"]?.jsonPrimitive?.content?.let { Base64.Default.decode(it) }
            val pending = o["pending"]?.jsonPrimitive?.content?.let { Base64.Default.decode(it) }
            val chain = o["chain"]?.jsonObject?.let {
                ChainWarning(
                    it.getValue("from").jsonPrimitive.long,
                    it.getValue("to").jsonPrimitive.long,
                    passwordUnchanged = it["pwu"]?.jsonPrimitive?.boolean ?: false,
                    unverified = it["unv"]?.jsonPrimitive?.boolean ?: true,
                )
            }
            val digests = LinkedHashMap<Long, String>()
            for ((revision, digest) in o.getValue("digests").jsonObject) {
                digests[revision.toLong()] = digest.jsonPrimitive.content
            }
            val state = VaultSyncState(
                baseFile = base,
                localFile = localFile,
                highestRevision = o.getValue("revision").jsonPrimitive.long,
                highestKeyEpoch = o.getValue("keyEpoch").jsonPrimitive.long,
                fileDigests = digests,
                pendingLocalFile = pending,
                chainWarning = chain,
                pendingHoldsNewerEdits = o["pendingAhead"]?.jsonPrimitive?.boolean ?: false,
                discardedPendingEpoch = o["discarded"]?.jsonPrimitive?.long,
            )
            if (state.highestRevision < 0 || state.highestKeyEpoch < 0) {
                throw LocalStateException("The sync state file holds invalid numbers")
            }
            vaults[id] = state
        }
        val servers = LinkedHashMap<String, ServerSyncState>()
        for ((key, element) in root.getValue("servers").jsonObject) {
            val o = element.jsonObject
            val caps = o["capabilities"]?.jsonObject?.let { c ->
                ServerCapabilities(
                    honoursIfMatch = c.getValue("ifMatch").jsonPrimitive.boolean,
                    acceptsMatchingIfMatch = c.getValue("acceptsMatching").jsonPrimitive.boolean,
                    honoursIfNoneMatchStar = c.getValue("ifNoneMatch").jsonPrimitive.boolean,
                    honoursIfMatchOnDelete = c.getValue("deleteIfMatch").jsonPrimitive.boolean,
                    etagChangesOnPut = c.getValue("etagChanges").jsonPrimitive.boolean,
                    putReturnsEtag = c.getValue("putEtag").jsonPrimitive.boolean,
                    strongEtags = c.getValue("strongEtags").jsonPrimitive.boolean,
                )
            }
            servers[key] = ServerSyncState(
                capabilities = caps,
                probedAtEpochMs = o["probedAt"]?.jsonPrimitive?.long ?: 0L,
            )
        }
        return LocalSyncState(vaults, servers, root["deviceId"]?.jsonPrimitive?.content)
    }

    // ------------------------------------------------------------------ writing

    private fun encode(state: LocalSyncState): ByteArray {
        val vaults = LinkedHashMap<String, JsonElement>()
        for ((id, v) in state.vaults) {
            val o = LinkedHashMap<String, JsonElement>()
            val base = v.baseFile
            if (base != null) o["base"] = JsonPrimitive(Base64.Default.encode(base))
            val localFile = v.localFile
            if (localFile != null) o["local"] = JsonPrimitive(Base64.Default.encode(localFile))
            o["revision"] = JsonPrimitive(v.highestRevision)
            o["keyEpoch"] = JsonPrimitive(v.highestKeyEpoch)
            v.pendingLocalFile?.let { o["pending"] = JsonPrimitive(Base64.Default.encode(it)) }
            v.chainWarning?.let {
                o["chain"] = JsonObject(
                    mapOf(
                        "from" to JsonPrimitive(it.fromEpoch),
                        "to" to JsonPrimitive(it.toEpoch),
                        "pwu" to JsonPrimitive(it.passwordUnchanged),
                        "unv" to JsonPrimitive(it.unverified),
                    ),
                )
            }
            if (v.pendingHoldsNewerEdits) o["pendingAhead"] = JsonPrimitive(true)
            v.discardedPendingEpoch?.let { o["discarded"] = JsonPrimitive(it) }
            val digests = LinkedHashMap<String, JsonElement>()
            for ((revision, digest) in v.fileDigests) digests[revision.toString()] = JsonPrimitive(digest)
            o["digests"] = JsonObject(digests)
            vaults[id] = JsonObject(o)
        }
        val servers = LinkedHashMap<String, JsonElement>()
        for ((key, s) in state.servers) {
            val o = LinkedHashMap<String, JsonElement>()
            o["probedAt"] = JsonPrimitive(s.probedAtEpochMs)
            val c = s.capabilities
            if (c != null) {
                o["capabilities"] = JsonObject(
                    mapOf(
                        "ifMatch" to JsonPrimitive(c.honoursIfMatch),
                        "acceptsMatching" to JsonPrimitive(c.acceptsMatchingIfMatch),
                        "ifNoneMatch" to JsonPrimitive(c.honoursIfNoneMatchStar),
                        "deleteIfMatch" to JsonPrimitive(c.honoursIfMatchOnDelete),
                        "etagChanges" to JsonPrimitive(c.etagChangesOnPut),
                        "putEtag" to JsonPrimitive(c.putReturnsEtag),
                        "strongEtags" to JsonPrimitive(c.strongEtags),
                    ),
                )
            }
            servers[key] = JsonObject(o)
        }
        val root = LinkedHashMap<String, JsonElement>()
        root["vaults"] = JsonObject(vaults)
        root["servers"] = JsonObject(servers)
        state.deviceId?.let { root["deviceId"] = JsonPrimitive(it) }
        return JsonObject(root).toString().encodeToByteArray()
    }

    private fun writeToDisk(state: LocalSyncState) {
        try {
            ensureDirectory()
            val payload = encode(state)
            val digest = MessageDigest.getInstance("SHA-256").digest(payload)
            // Created owner-only (POSIX) at creation, never widened afterwards: the temp file is the future state file.
            Files.deleteIfExists(tempFile.toPath())
            FileChannel.open(
                tempFile.toPath(), setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), *fileAttributes(),
            ).use { channel ->
                val buffer = ByteBuffer.allocate(MAGIC.size + 1 + digest.size + payload.size)
                buffer.put(MAGIC).put(VERSION).put(digest).put(payload).flip()
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            beforeRenameHook?.invoke()
            // Rolling previous copy: the current file becomes .prev first (only .prev exists between the two renames).
            if (stateFile.exists()) moveReplacing(stateFile, prevFile)
            betweenRenamesHook?.invoke()
            moveReplacing(tempFile, stateFile)
            syncDirectory()
            stamp = statFile()
            loadedFromPrevious = false
        } catch (e: LocalStateException) {
            throw e
        } catch (e: IOException) {
            throw LocalStateException("The sync state cannot be written", e)
        }
    }

    /**
     * Renames [source] over [target]: an atomic move; on a sharing violation (Windows, a scanner holding the target
     * open without `FILE_SHARE_DELETE`) or any other failure it retries a few times over about a second, and as a
     * last resort replaces non-atomically. The fallback is safe because the previous copy is already in place.
     */
    private fun moveReplacing(source: File, target: File) {
        var lastFailure: IOException? = null
        for (attempt in 1..MOVE_ATTEMPTS) {
            try {
                Files.move(source.toPath(), target.toPath(), StandardCopyOption.ATOMIC_MOVE)
                return
            } catch (e: AtomicMoveNotSupportedException) {
                lastFailure = e
                break // retrying cannot help: go to the plain replace
            } catch (e: IOException) {
                lastFailure = e
                if (attempt < MOVE_ATTEMPTS) Thread.sleep(MOVE_RETRY_MILLIS)
            }
        }
        try {
            Files.move(source.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        } catch (e: IOException) {
            e.addSuppressed(lastFailure ?: e)
            throw LocalStateException("The sync state cannot be replaced", e)
        }
    }

    /** Makes the rename durable on POSIX systems; not possible (and not needed) on Windows. */
    private fun syncDirectory() {
        try {
            FileChannel.open(dir.toPath(), StandardOpenOption.READ).use { it.force(true) }
        } catch (e: IOException) {
            // Unsupported on this platform.
        } catch (e: UnsupportedOperationException) {
            // Same.
        }
    }

    companion object {
        const val DEFAULT_FILE_NAME = "terminalmax-sync-state.bin"
        private val MAGIC = byteArrayOf(0x54, 0x4D, 0x58, 0x53) // "TMXS"
        private const val VERSION: Byte = 1
        private const val DIGEST_BYTES = 32
        private const val MAX_STATE_BYTES = 64L * 1024 * 1024
        private const val MOVE_ATTEMPTS = 5
        private const val MOVE_RETRY_MILLIS = 250L
        private val mutexes = ConcurrentHashMap<String, Mutex>()

        /** Canonical lock-file paths of the directories this process holds (see [lockDirectory]). */
        private val openDirectories = ConcurrentHashMap<String, Any>()
        private val OWNER_DIR = PosixFilePermissions.fromString("rwx------")
        private val OWNER_FILE = PosixFilePermissions.fromString("rw-------")
    }
}
