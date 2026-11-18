// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

/** The vault file as stored remotely. [etag] is the raw `ETag` header value (may be weak or absent). */
class RemoteFile(val bytes: ByteArray, val etag: String?) {
    override fun toString(): String = "RemoteFile(${bytes.size} bytes, etag=$etag)"
}

/**
 * What the server was observed to do, as measured by [RemoteStore.probe].
 *
 * @property honoursIfMatch a PUT with a non-matching `If-Match` is rejected with 412 and changes nothing
 * @property honoursIfNoneMatchStar a PUT with `If-None-Match: *` on an existing file is rejected and changes nothing
 * @property etagChangesOnPut the ETag changes when a PUT replaces the content with different bytes of the same size
 * @property putReturnsEtag successful PUT responses carry an `ETag` header
 * @property strongEtags the ETags the server returns are strong (quoted, not `W/`)
 */
data class ServerCapabilities(
    val honoursIfMatch: Boolean,
    val honoursIfNoneMatchStar: Boolean,
    val etagChangesOnPut: Boolean,
    val putReturnsEtag: Boolean,
    val strongEtags: Boolean,
) {
    /** True when every write to the vault file can be made atomic with conditional requests alone. */
    val supportsConditionalWrites: Boolean
        get() = honoursIfMatch && honoursIfNoneMatchStar && etagChangesOnPut && strongEtags
}

sealed interface WriteResult {
    /** Stored. [etag] is the ETag from the PUT response, if the server sent one. */
    data class Written(val etag: String?) : WriteResult

    /** The `If-Match` / `If-None-Match` precondition failed (HTTP 412, or 404 for `If-Match`). */
    data object PreconditionFailed : WriteResult

    /** The server refused or failed the write for another reason. */
    data class Failed(val message: String) : WriteResult
}

/** Transport-level failure (network, unexpected HTTP status, oversized or rejected response). */
open class RemoteIoException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The server rejected the credentials (HTTP 401/403). */
class RemoteAuthException(message: String) : RemoteIoException(message)

/**
 * A single remote vault file plus a lock file, as offered by a WebDAV collection.
 * All methods may throw [RemoteIoException].
 */
interface RemoteStore {
    /** Measures server behaviour using a scratch file; never touches the vault file. */
    suspend fun probe(): ServerCapabilities

    /** The vault file, or null when it does not exist. */
    suspend fun read(): RemoteFile?

    /**
     * Writes the vault file. [ifMatchEtag] (a strong ETag) becomes `If-Match`; [ifNoneMatch] sends
     * `If-None-Match: *` (create only).
     */
    suspend fun write(bytes: ByteArray, ifMatchEtag: String?, ifNoneMatch: Boolean): WriteResult

    suspend fun readLock(): RemoteFile?

    suspend fun writeLock(bytes: ByteArray, ifNoneMatch: Boolean): WriteResult

    /** Deletes the lock file; true when it is gone afterwards (including "was not there"). */
    suspend fun deleteLock(): Boolean
}

/** True for a strong, quoted entity tag such as `"abc"`; false for `W/"abc"`, unquoted or absent values. */
fun isStrongEtag(etag: String?): Boolean =
    etag != null && etag.length >= 2 && etag.startsWith('"') && etag.endsWith('"') &&
        etag.indexOf('"', 1) == etag.length - 1
