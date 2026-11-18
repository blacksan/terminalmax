// SPDX-License-Identifier: GPL-3.0-or-later
@file:OptIn(kotlin.io.encoding.ExperimentalEncodingApi::class)

package org.terminalmax.core.sync

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.nio.channels.OverlappingFileLockException
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import kotlin.io.encoding.Base64
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
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

/**
 * File-backed [LocalStateStore]: the rollback floors, the merge base (the encrypted file as last synced), the
 * file digests used for fork detection, and the per-server probe result survive restarts, so rollback protection
 * does not reset every time the OS kills the app.
 *
 * Layout: one state file, `<directory>/<fileName>`. It holds `"TMXS" | u8 version | SHA-256(payload) | payload`
 * where the payload is JSON: the floors, digests and probe results, the base file, and (when a `VaultSession` owns the
 * directory) the sealed local vault file and the device id. **That single file is the manifest**: it is replaced
 * atomically, so the local vault and the sync state cannot diverge after a crash. It contains no plaintext secrets
 * (the vault files are ciphertext), but it should still live in the app's private storage; whoever can rewrite it can
 * lower the floors or substitute an older local vault.
 *
 * Atomicity: [save] writes `<fileName>.tmp` completely, forces it to disk (`fsync`), then renames it over the
 * state file with an atomic move and forces the directory. A crash at any point leaves either the old state or the
 * new one; a leftover temp file is ignored and overwritten by the next save. The checksum catches torn or
 * damaged files: [load] then throws [LocalStateException] and the engine fails closed, because silently starting
 * from an empty state would switch rollback protection off. [reset] is the explicit way out.
 *
 * Concurrency: [exclusive] holds a per-path mutex (same process) and an OS file lock on `<fileName>.lock` (other
 * processes) for the duration of a sync, so two engines can never interleave their load/save steps.
 *
 * @param directory a directory supplied by the app (for example `context.filesDir` + "/sync"); created if missing
 */
class FileLocalStateStore(directory: File, fileName: String = DEFAULT_FILE_NAME) : LocalStateStore {
    private val dir: File = directory.absoluteFile
    private val stateFile = File(dir, fileName)
    private val tempFile = File(dir, "$fileName.tmp")
    private val lockFile = File(dir, "$fileName.lock")

    @Volatile
    private var cached: LocalSyncState? = null

    /** Test hook: runs after the temp file is durable and before it is renamed (to simulate a crash there). */
    internal var beforeRenameHook: (() -> Unit)? = null

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
        val key = try {
            stateFile.canonicalPath
        } catch (e: IOException) {
            stateFile.absolutePath
        }
        val mutex = mutexes.computeIfAbsent(key) { Mutex() }
        return mutex.withLock {
            cached = null // another process may have changed the file since this instance last looked
            val channel = withContext(Dispatchers.IO) { openLockChannel() }
            try {
                val fileLock = acquire(channel)
                try {
                    block()
                } finally {
                    try {
                        fileLock.release()
                    } catch (e: IOException) {
                        // The lock goes away when the channel is closed.
                    }
                }
            } finally {
                try {
                    channel.close()
                } catch (e: IOException) {
                    // Nothing more to do.
                }
            }
        }
    }

    /**
     * Deletes the stored state (an explicit user decision: it switches rollback protection off for a fresh start).
     * Takes the same per-path mutex and file lock as [exclusive], so it cannot race a running sync; call it outside
     * [exclusive].
     */
    suspend fun reset() {
        exclusive {
            withContext(Dispatchers.IO) {
                stateFile.delete()
                tempFile.delete()
            }
            cached = null
        }
    }

    // ------------------------------------------------------------------ locking

    private fun openLockChannel(): FileChannel {
        try {
            if (!dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) {
                throw LocalStateException("The sync state directory cannot be created")
            }
            return FileChannel.open(lockFile.toPath(), StandardOpenOption.CREATE, StandardOpenOption.WRITE)
        } catch (e: IOException) {
            throw LocalStateException("The sync state lock cannot be opened", e)
        }
    }

    private suspend fun acquire(channel: FileChannel): FileLock {
        val deadline = System.nanoTime() + LOCK_WAIT_NANOS
        while (true) {
            val lock: FileLock? = try {
                withContext(Dispatchers.IO) { channel.tryLock() }
            } catch (e: OverlappingFileLockException) {
                null
            } catch (e: IOException) {
                throw LocalStateException("The sync state lock cannot be taken", e)
            }
            if (lock != null) return lock
            if (System.nanoTime() > deadline) throw LocalStateException("The sync state is in use by another process")
            delay(LOCK_POLL_MILLIS)
        }
    }

    // ------------------------------------------------------------------ reading

    private fun readFromDisk(): LocalSyncState {
        if (!stateFile.exists()) return LocalSyncState()
        try {
            if (stateFile.length() > MAX_STATE_BYTES) throw LocalStateException("The sync state file is too large")
            val bytes = stateFile.readBytes()
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

    private fun decode(text: String): LocalSyncState {
        val root = Json.parseToJsonElement(text).jsonObject
        val vaults = LinkedHashMap<String, VaultSyncState>()
        for ((id, element) in root.getValue("vaults").jsonObject) {
            val o = element.jsonObject
            val base = o["base"]?.jsonPrimitive?.content?.let { Base64.Default.decode(it) }
            val localFile = o["local"]?.jsonPrimitive?.content?.let { Base64.Default.decode(it) }
            val digests = LinkedHashMap<Long, String>()
            for ((revision, digest) in o.getValue("digests").jsonObject) {
                digests[revision.toLong()] = digest.jsonPrimitive.content
            }
            val state = VaultSyncState(
                baseFile = base,
                localFile = localFile,
                highestRevision = o.getValue("revision").jsonPrimitive.long,
                highestKeyEpoch = o.getValue("keyEpoch").jsonPrimitive.long,
                highestHeaderRevision = o.getValue("headerRevision").jsonPrimitive.long,
                fileDigests = digests,
            )
            if (state.highestRevision < 0 || state.highestKeyEpoch < 0 || state.highestHeaderRevision < 0) {
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
            o["headerRevision"] = JsonPrimitive(v.highestHeaderRevision)
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
            if (!dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) {
                throw LocalStateException("The sync state directory cannot be created")
            }
            val payload = encode(state)
            val digest = MessageDigest.getInstance("SHA-256").digest(payload)
            FileOutputStream(tempFile).use { out ->
                out.write(MAGIC)
                out.write(VERSION.toInt())
                out.write(digest)
                out.write(payload)
                out.flush()
                out.fd.sync()
            }
            beforeRenameHook?.invoke()
            try {
                Files.move(tempFile.toPath(), stateFile.toPath(), StandardCopyOption.ATOMIC_MOVE)
            } catch (e: AtomicMoveNotSupportedException) {
                throw LocalStateException("This file system cannot replace the sync state atomically", e)
            }
            syncDirectory()
        } catch (e: LocalStateException) {
            throw e
        } catch (e: IOException) {
            throw LocalStateException("The sync state cannot be written", e)
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
        private const val LOCK_WAIT_NANOS = 30_000_000_000L
        private const val LOCK_POLL_MILLIS = 100L
        private val mutexes = ConcurrentHashMap<String, Mutex>()
    }
}
