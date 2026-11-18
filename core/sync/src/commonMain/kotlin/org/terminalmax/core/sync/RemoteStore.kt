// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

/** The vault file as stored remotely. [etag] is the raw `ETag` header value (may be weak, malformed or absent). */
class RemoteFile(val bytes: ByteArray, val etag: String?) {
    override fun toString(): String = "RemoteFile(${bytes.size} bytes, etag=$etag)"
}

/**
 * What the server was observed to do, as measured by [RemoteStore.probe]. The probe measures behaviour of a scratch
 * file; a server can in principle treat the vault file differently, which is why the engine also reads every upload
 * back and why the merge is a monotone join (see the README).
 *
 * @property honoursIfMatch a PUT with a non-matching `If-Match` is rejected with 412 and changes nothing
 * @property acceptsMatchingIfMatch a PUT with the ETag the server returned from GET is accepted and applied
 * @property honoursIfNoneMatchStar a PUT with `If-None-Match: *` on an existing file is rejected and changes nothing
 * @property honoursIfMatchOnDelete a DELETE with a non-matching `If-Match` is rejected and deletes nothing
 * @property etagChangesOnPut the ETag changes when a PUT replaces the content with different bytes of the same size
 * @property putReturnsEtag successful PUT responses carry an `ETag` header
 * @property strongEtags the ETags the server returns from GET are strong, quoted and header-safe (see [isStrongEtag])
 */
data class ServerCapabilities(
    val honoursIfMatch: Boolean,
    val acceptsMatchingIfMatch: Boolean,
    val honoursIfNoneMatchStar: Boolean,
    val honoursIfMatchOnDelete: Boolean,
    val etagChangesOnPut: Boolean,
    val putReturnsEtag: Boolean,
    val strongEtags: Boolean,
) {
    /** True when every write to the vault file can be made atomic with conditional requests alone. */
    val supportsConditionalWrites: Boolean
        get() = honoursIfMatch && acceptsMatchingIfMatch && honoursIfNoneMatchStar && etagChangesOnPut && strongEtags

    /** True when lock-file replacement and deletion can be made conditional on the ETag that was read. */
    val supportsConditionalLocks: Boolean
        get() = honoursIfMatch && acceptsMatchingIfMatch && honoursIfMatchOnDelete && etagChangesOnPut && strongEtags
}

sealed interface WriteResult {
    /** Stored. [etag] is the ETag from the PUT response, if the server sent one. */
    data class Written(val etag: String?) : WriteResult

    /** The `If-Match` / `If-None-Match` precondition failed (HTTP 412, or 404 for `If-Match`). */
    data object PreconditionFailed : WriteResult

    /** The server refused or failed the write for another reason. */
    data class Failed(val message: String) : WriteResult
}

enum class DeleteResult {
    /** The file is gone (it was deleted, or it was not there). */
    Deleted,

    /** The `If-Match` precondition failed: the file is not the one that was read. Nothing was deleted. */
    PreconditionFailed,

    /** The server refused or failed the delete. */
    Failed,
}

/** Transport-level failure (network, unexpected HTTP status, oversized or rejected response). */
open class RemoteIoException(message: String, cause: Throwable? = null) : Exception(message, cause)

/** The server rejected the credentials (HTTP 401/403). */
class RemoteAuthException(message: String) : RemoteIoException(message)

/**
 * A single remote vault file plus a lock file, as offered by a WebDAV collection.
 * All methods may throw [RemoteIoException] and nothing else (except cancellation).
 */
interface RemoteStore {
    /**
     * Identifies the server and account (normalised collection URL plus user name). Per-server facts such as the
     * probe result are bound to it, so changing the URL or account never reuses them.
     */
    val serverKey: String

    /**
     * The server's own clock (HTTP `Date` header) from the most recent response that carried one, in epoch
     * milliseconds, or null when the server never sent one. Lock leases are measured on this clock, so clock skew
     * between devices does not matter.
     */
    val lastServerDateMillis: Long?

    /** Measures server behaviour using a scratch file; never touches the vault file. */
    suspend fun probe(): ServerCapabilities

    /** The vault file, or null when it does not exist. */
    suspend fun read(): RemoteFile?

    /**
     * Writes the vault file. [ifMatchEtag] (a strong ETag, see [isStrongEtag]) becomes `If-Match`; [ifNoneMatch]
     * sends `If-None-Match: *` (create only).
     */
    suspend fun write(bytes: ByteArray, ifMatchEtag: String?, ifNoneMatch: Boolean): WriteResult

    suspend fun readLock(): RemoteFile?

    suspend fun writeLock(bytes: ByteArray, ifMatchEtag: String?, ifNoneMatch: Boolean): WriteResult

    /** Deletes the lock file, conditionally on [ifMatchEtag] when given. */
    suspend fun deleteLock(ifMatchEtag: String?): DeleteResult
}

private const val MAX_ETAG_CHARS = 258 // two quotes plus 256 characters

/**
 * True for a strong, quoted entity tag whose characters can be echoed into a request header: `"` followed by 1 to
 * 256 visible ASCII characters other than `"`, followed by `"`. False for `W/"abc"`, unquoted, empty, over-long or
 * non-ASCII values, and for `null`. (A server may legally send `obs-text` or DEL in an ETag; OkHttp refuses to send
 * such a value back, so it is treated as "no ETag" instead.)
 */
fun isStrongEtag(etag: String?): Boolean {
    if (etag == null || etag.length < 3 || etag.length > MAX_ETAG_CHARS) return false
    if (etag[0] != '"' || etag[etag.length - 1] != '"') return false
    for (i in 1 until etag.length - 1) {
        val c = etag[i].code
        if (c < 0x21 || c > 0x7E || c == 0x22) return false
    }
    return true
}

/** [etag] if it is usable in `If-Match`, otherwise null. */
fun usableEtag(etag: String?): String? = if (isStrongEtag(etag)) etag else null
