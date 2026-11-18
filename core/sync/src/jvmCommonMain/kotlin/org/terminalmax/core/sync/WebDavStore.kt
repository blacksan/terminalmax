// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Credentials
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.ResponseBody

/**
 * [RemoteStore] over a WebDAV collection, using OkHttp.
 *
 * Security properties:
 *  - HTTPS is required unless the host is `localhost`, `127.0.0.1` or `::1`, or [allowInsecureHttp] is set; the
 *    constructor throws otherwise, so credentials can never be sent in clear text to a remote host by accident.
 *  - Basic auth is sent preemptively on every request (only ever to the configured origin).
 *  - Redirects are never followed automatically. Same-origin (scheme, host, port) 307/308 redirects (and
 *    301/302/303 for GET) are followed manually up to 3 times; any redirect to another origin fails the request
 *    before a single byte (or credential) is sent there.
 *  - Only strong, quoted ETags are ever used in `If-Match`.
 *  - Response bodies are capped at [maxResponseBytes] (32 MiB by default); PROPFIND responses at 1 MiB.
 *  - PROPFIND responses are scanned by [PropfindParser], which cannot be made to resolve entities.
 *
 * @param baseUrl URL of the WebDAV collection that holds the files (a trailing slash is added if missing)
 * @param password is copied into the Authorization header; the array is neither modified nor retained
 * @param httpClient used as a template: redirects are always disabled on the derived client
 */
class WebDavStore(
    baseUrl: String,
    username: String,
    password: CharArray,
    private val fileName: String = DEFAULT_FILE_NAME,
    httpClient: OkHttpClient = defaultHttpClient(),
    allowInsecureHttp: Boolean = false,
    lockFileName: String = DEFAULT_LOCK_FILE_NAME,
    private val maxResponseBytes: Int = MAX_RESPONSE_BYTES,
) : RemoteStore {

    private val collection: HttpUrl
    private val fileUrl: HttpUrl
    private val lockUrl: HttpUrl
    private val authorization: String
    private val client: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()
    private val random = SecureRandom()

    init {
        require(NAME_PATTERN.matches(fileName) && NAME_PATTERN.matches(lockFileName)) { "Invalid file name" }
        val parsed = baseUrl.toHttpUrlOrNull() ?: throw IllegalArgumentException("Invalid WebDAV URL")
        require(parsed.username.isEmpty() && parsed.password.isEmpty()) { "Credentials must not be part of the URL" }
        if (parsed.scheme == "http") {
            require(allowInsecureHttp || isLoopbackHost(parsed.host)) {
                "Refusing to send credentials over plain HTTP to a non-local host"
            }
        }
        collection = if (parsed.encodedPath.endsWith("/")) parsed else parsed.newBuilder().addPathSegment("").build()
        fileUrl = collection.newBuilder().addPathSegment(fileName).build()
        lockUrl = collection.newBuilder().addPathSegment(lockFileName).build()
        authorization = Credentials.basic(username, String(password), StandardCharsets.UTF_8)
    }

    // ------------------------------------------------------------------ RemoteStore

    override suspend fun probe(): ServerCapabilities = withContext(Dispatchers.IO) { runProbe() }

    override suspend fun read(): RemoteFile? = withContext(Dispatchers.IO) { getFile(fileUrl) }

    override suspend fun write(bytes: ByteArray, ifMatchEtag: String?, ifNoneMatch: Boolean): WriteResult =
        withContext(Dispatchers.IO) { putFile(fileUrl, bytes, ifMatchEtag, ifNoneMatch) }

    override suspend fun readLock(): RemoteFile? = withContext(Dispatchers.IO) { getFile(lockUrl) }

    override suspend fun writeLock(bytes: ByteArray, ifNoneMatch: Boolean): WriteResult =
        withContext(Dispatchers.IO) { putFile(lockUrl, bytes, null, ifNoneMatch) }

    override suspend fun deleteLock(): Boolean = withContext(Dispatchers.IO) {
        val reply = send("DELETE", lockUrl)
        reply.code in 200..299 || reply.code == 404
    }

    // ------------------------------------------------------------------ operations

    private fun getFile(url: HttpUrl): RemoteFile? {
        val reply = send("GET", url)
        return when {
            reply.code == 404 -> null
            reply.code in 200..299 -> RemoteFile(reply.bytes, reply.etag)
            else -> throw RemoteIoException("GET failed with HTTP ${reply.code}")
        }
    }

    private fun putFile(url: HttpUrl, bytes: ByteArray, ifMatchEtag: String?, ifNoneMatch: Boolean): WriteResult {
        if (ifMatchEtag != null && !isStrongEtag(ifMatchEtag)) {
            return WriteResult.Failed("Refusing to send a weak or malformed ETag in If-Match")
        }
        val headers = LinkedHashMap<String, String>()
        if (ifMatchEtag != null) headers["If-Match"] = ifMatchEtag
        if (ifNoneMatch) headers["If-None-Match"] = "*"
        var reply = send("PUT", url, headers, bytes, "application/octet-stream")
        if (reply.code == 409) {
            // Parent collection missing: create it once and retry.
            ensureCollection()
            reply = send("PUT", url, headers, bytes, "application/octet-stream")
        }
        return when {
            reply.code in 200..299 -> WriteResult.Written(reply.etag)
            reply.code == 412 -> WriteResult.PreconditionFailed
            reply.code == 404 && ifMatchEtag != null -> WriteResult.PreconditionFailed
            else -> WriteResult.Failed("PUT failed with HTTP ${reply.code}")
        }
    }

    /** MKCOL on the collection; "already exists" (405) and most other answers are fine. */
    private fun ensureCollection() {
        try {
            send("MKCOL", collection)
        } catch (e: RemoteAuthException) {
            throw e
        } catch (e: RemoteIoException) {
            // Best effort; the following request will report any real problem.
        }
    }

    /** ETag via PROPFIND (Depth 0), or null when unavailable or the XML was rejected. */
    private fun propfindEtag(url: HttpUrl): String? {
        val reply = try {
            send("PROPFIND", url, mapOf("Depth" to "0"), PROPFIND_BODY.toByteArray(), "application/xml", PROPFIND_LIMIT)
        } catch (e: RemoteAuthException) {
            throw e
        } catch (e: RemoteIoException) {
            return null
        }
        if (reply.code !in 200..299) return null
        return try {
            PropfindParser.extractEtag(reply.bytes.decodeToString())
        } catch (e: XmlRejectedException) {
            null
        }
    }

    private fun currentEtag(url: HttpUrl): String? = propfindEtag(url) ?: getFile(url)?.etag

    private fun runProbe(): ServerCapabilities {
        ensureCollection()
        val scratch = collection.newBuilder().addPathSegment("terminalmax.probe-" + randomHex(8)).build()
        try {
            val first = randomBytes(24)
            val created = putFile(scratch, first, null, false)
            if (created !is WriteResult.Written) throw RemoteIoException("Probe could not create a scratch file")
            var current = first
            var everyPutHadEtag = created.etag != null

            val strongObserved = ArrayList<Boolean>()
            val etag0 = currentEtag(scratch)
            strongObserved += isStrongEtag(etag0)

            // (1) A bogus If-Match must be rejected with 412 and leave the content unchanged.
            val bogus = "\"tmx-bogus-" + randomHex(6) + "\""
            val ifMatchAttempt = randomBytes(24)
            val r1 = putFile(scratch, ifMatchAttempt, bogus, false)
            var after = getFile(scratch)?.bytes
            val honoursIfMatch = r1 is WriteResult.PreconditionFailed && after != null && after.contentEquals(current)
            if (after != null) current = after

            // (2) If-None-Match: * on an existing file must not overwrite it.
            val ifNoneMatchAttempt = randomBytes(24)
            val r2 = putFile(scratch, ifNoneMatchAttempt, null, true)
            after = getFile(scratch)?.bytes
            val honoursIfNoneMatch = r2 is WriteResult.PreconditionFailed && after != null && after.contentEquals(current)
            if (after != null) current = after

            // (3) The ETag must change when same-size content is replaced. Two consecutive replacements are
            // compared so a timestamp-resolution boundary cannot make a weak scheme look good.
            var etagChanges = true
            var previousEtag = currentEtag(scratch)
            repeat(2) {
                val next = randomBytes(24)
                val r = putFile(scratch, next, null, false)
                if (r !is WriteResult.Written) throw RemoteIoException("Probe could not update the scratch file")
                if (r.etag == null) everyPutHadEtag = false
                val updated = currentEtag(scratch)
                strongObserved += isStrongEtag(updated)
                if (previousEtag == null || updated == null || previousEtag == updated) etagChanges = false
                previousEtag = updated
            }

            return ServerCapabilities(
                honoursIfMatch = honoursIfMatch,
                honoursIfNoneMatchStar = honoursIfNoneMatch,
                etagChangesOnPut = etagChanges,
                putReturnsEtag = everyPutHadEtag,
                strongEtags = strongObserved.all { it },
            )
        } finally {
            try {
                send("DELETE", scratch)
            } catch (e: RemoteIoException) {
                // Best effort cleanup.
            }
        }
    }

    // ------------------------------------------------------------------ HTTP

    private class Reply(val code: Int, val etag: String?, val bytes: ByteArray)

    /**
     * One request with manual, same-origin-only redirect handling. Authorization is attached only to URLs on the
     * configured origin, and redirects are validated before they are followed.
     */
    private fun send(
        method: String,
        url: HttpUrl,
        headers: Map<String, String> = emptyMap(),
        body: ByteArray? = null,
        contentType: String? = null,
        limit: Int = maxResponseBytes,
    ): Reply {
        var target = url
        var redirects = 0
        while (true) {
            check(sameOrigin(target)) { "Request target is not on the configured origin" }
            val requestBody: RequestBody? = body?.toRequestBody(contentType?.toMediaType())
            val builder = Request.Builder().url(target).header("Authorization", authorization)
            for ((k, v) in headers) builder.header(k, v)
            val request = builder.method(method, requestBody).build()
            try {
                client.newCall(request).execute().use { response ->
                    val code = response.code
                    if (code in REDIRECT_CODES) {
                        val location = response.header("Location")
                            ?: throw RemoteIoException("Redirect without Location")
                        val next = response.request.url.resolve(location)
                            ?: throw RemoteIoException("Invalid redirect target")
                        if (!sameOrigin(next)) throw RemoteIoException("Redirect to a different host was refused")
                        val preservesMethod = code == 307 || code == 308
                        if (!preservesMethod && method != "GET" && method != "HEAD") {
                            throw RemoteIoException("Unsupported redirect (HTTP $code) for $method")
                        }
                        if (++redirects > MAX_REDIRECTS) throw RemoteIoException("Too many redirects")
                        target = next
                        return@use null
                    }
                    if (code == 401 || code == 403) throw RemoteAuthException("Server rejected the credentials (HTTP $code)")
                    return Reply(code, response.header("ETag"), readCapped(response.body, limit))
                }
            } catch (e: IOException) {
                throw RemoteIoException("Network error (${e.javaClass.simpleName})", e)
            }
        }
    }

    private fun readCapped(body: ResponseBody?, limit: Int): ByteArray {
        if (body == null) return ByteArray(0)
        if (body.contentLength() > limit) throw RemoteIoException("Response too large")
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        body.byteStream().use { stream ->
            while (true) {
                val n = stream.read(buffer)
                if (n < 0) break
                total += n
                if (total > limit) throw RemoteIoException("Response too large")
                out.write(buffer, 0, n)
            }
        }
        return out.toByteArray()
    }

    private fun sameOrigin(u: HttpUrl): Boolean =
        u.scheme == collection.scheme && u.host == collection.host && u.port == collection.port

    private fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    private fun randomHex(bytes: Int): String =
        randomBytes(bytes).joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }

    companion object {
        const val DEFAULT_FILE_NAME = "terminalmax.vault"
        const val DEFAULT_LOCK_FILE_NAME = "terminalmax.lock"
        const val MAX_RESPONSE_BYTES = 32 * 1024 * 1024
        private const val PROPFIND_LIMIT = 1024 * 1024
        private const val MAX_REDIRECTS = 3
        private val REDIRECT_CODES = setOf(301, 302, 303, 307, 308)
        private val NAME_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")
        private const val PROPFIND_BODY =
            "<?xml version=\"1.0\" encoding=\"utf-8\"?><propfind xmlns=\"DAV:\"><prop><getetag/></prop></propfind>"

        /** OkHttp client with conservative timeouts. */
        fun defaultHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .callTimeout(2, TimeUnit.MINUTES)
            .followRedirects(false)
            .followSslRedirects(false)
            .build()

        /** Hosts for which plain HTTP is acceptable without an explicit opt-in. */
        fun isLoopbackHost(host: String): Boolean =
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]"
    }
}
