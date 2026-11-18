// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors

/** A tiny in-process WebDAV server (GET/PUT/DELETE/MKCOL/PROPFIND) with configurable misbehaviour. */
class FakeDavServer(var config: Config = Config()) : AutoCloseable {

    enum class EtagStyle {
        /** Quoted hash of the content: changes whenever the content changes. */
        STRONG,

        /** `W/"hash"`. */
        WEAK,

        /** Quoted `size-mtime` with a fixed mtime: does not change for same-size writes. */
        MTIME_SIZE,
    }

    data class Config(
        val etagStyle: EtagStyle = EtagStyle.STRONG,
        val honourIfMatch: Boolean = true,
        val honourIfNoneMatch: Boolean = true,
        val etagOnPut: Boolean = true,
        val escapeQuotesInXml: Boolean = true,
        val credentials: Pair<String, String>? = null,
        val collectionExists: Boolean = true,
        /** Replaces every PROPFIND body when set (used for XXE and hostile-XML tests). */
        val propfindOverride: String? = null,
        /** DELETE with a non-matching `If-Match` is answered with 412 and deletes nothing. */
        val honourIfMatchOnDelete: Boolean = true,
        /** Every PUT carrying `If-Match` is answered with 412, even with the correct ETag. */
        val rejectAllIfMatch: Boolean = false,
        /** When set, every file gets exactly this ETag (used for hostile-ETag tests). */
        val etagOverride: String? = null,
    )

    class Logged(
        val method: String,
        val path: String,
        val authorization: String?,
        val ifMatch: String?,
        val ifNoneMatch: String?,
    )

    val files = ConcurrentHashMap<String, ByteArray>()
    val log = CopyOnWriteArrayList<Logged>()

    /** Runs once, right before the next vault PUT is evaluated (simulates a concurrent writer). */
    @Volatile
    var beforeNextPut: (() -> Unit)? = null

    /** Runs once, at the first GET of the vault file that follows a successful vault PUT. */
    @Volatile
    var afterPutBeforeNextGet: (() -> Unit)? = null

    /**
     * Runs before every request is evaluated (under the server lock, so it may change [files]); set it back to
     * null inside the callback for a one-shot hook.
     */
    @Volatile
    var beforeRequest: ((method: String, name: String) -> Unit)? = null

    @Volatile
    private var putSinceGet = false

    @Volatile
    private var collectionCreated = true

    private val lock = Any()
    private val server: HttpServer = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
    private val executor = Executors.newCachedThreadPool()

    val port: Int get() = server.address.port
    val baseUrl: String get() = "http://127.0.0.1:$port/dav/"

    init {
        collectionCreated = config.collectionExists
        server.createContext("/") { exchange ->
            try {
                synchronized(lock) { handle(exchange) }
            } catch (e: Throwable) {
                runCatching { exchange.sendResponseHeaders(500, -1) }
            } finally {
                exchange.close()
            }
        }
        server.executor = executor
        server.start()
    }

    fun etagOf(bytes: ByteArray): String {
        config.etagOverride?.let { return it }
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }.take(16)
        return when (config.etagStyle) {
            EtagStyle.STRONG -> "\"$hash\""
            EtagStyle.WEAK -> "W/\"$hash\""
            EtagStyle.MTIME_SIZE -> "\"${bytes.size}-1700000000\""
        }
    }

    fun requests(method: String, name: String? = null) =
        log.filter { it.method == method && (name == null || it.path == "/dav/$name") }

    private fun respond(ex: HttpExchange, code: Int, body: ByteArray = ByteArray(0), headers: Map<String, String> = emptyMap()) {
        for ((k, v) in headers) ex.responseHeaders.add(k, v)
        val noBody = body.isEmpty() || ex.requestMethod == "HEAD" || code == 204 || code == 304
        ex.sendResponseHeaders(code, if (noBody) -1 else body.size.toLong())
        if (!noBody) ex.responseBody.use { it.write(body) }
    }

    private fun handle(ex: HttpExchange) {
        val path = ex.requestURI.path
        val method = ex.requestMethod
        val auth = ex.requestHeaders.getFirst("Authorization")
        log += Logged(method, path, auth, ex.requestHeaders.getFirst("If-Match"), ex.requestHeaders.getFirst("If-None-Match"))
        val body = ex.requestBody.readBytes()

        config.credentials?.let { (user, pass) ->
            val expected = "Basic " + Base64.getEncoder().encodeToString("$user:$pass".toByteArray())
            if (auth != expected) {
                respond(ex, 401, headers = mapOf("WWW-Authenticate" to "Basic realm=\"test\""))
                return
            }
        }
        if (!path.startsWith("/dav/")) {
            respond(ex, 404)
            return
        }
        val name = path.removePrefix("/dav/")
        beforeRequest?.invoke(method, name)
        when (method) {
            "GET", "HEAD" -> get(ex, name)
            "PUT" -> put(ex, name, body)
            "DELETE" -> delete(ex, name)
            "MKCOL" -> if (name.isEmpty() && !collectionCreated) {
                collectionCreated = true
                respond(ex, 201)
            } else {
                respond(ex, 405)
            }
            "PROPFIND" -> propfind(ex, name)
            else -> respond(ex, 405)
        }
    }

    private fun delete(ex: HttpExchange, name: String) {
        val existing = files[name]
        val ifMatch = ex.requestHeaders.getFirst("If-Match")
        if (config.honourIfMatchOnDelete && ifMatch != null) {
            val current = existing?.let { etagOf(it) }
            val ok = current != null && (ifMatch.trim() == "*" || ifMatch.split(",").any { it.trim() == current && !it.trim().startsWith("W/") })
            if (!ok) {
                respond(ex, 412)
                return
            }
        }
        if (files.remove(name) != null) respond(ex, 204) else respond(ex, 404)
    }

    private fun get(ex: HttpExchange, name: String) {
        if (name == VAULT && putSinceGet) {
            putSinceGet = false
            afterPutBeforeNextGet?.let {
                afterPutBeforeNextGet = null
                it()
            }
        }
        val bytes = files[name]
        if (bytes == null) {
            respond(ex, 404)
            return
        }
        respond(ex, 200, bytes, mapOf("ETag" to etagOf(bytes)))
    }

    private fun put(ex: HttpExchange, name: String, body: ByteArray) {
        if (name == VAULT) {
            beforeNextPut?.let {
                beforeNextPut = null
                it()
            }
        }
        if (!collectionCreated) {
            respond(ex, 409)
            return
        }
        val existing = files[name]
        val currentEtag = existing?.let { etagOf(it) }
        val ifMatch = ex.requestHeaders.getFirst("If-Match")
        val ifNoneMatch = ex.requestHeaders.getFirst("If-None-Match")
        if (config.rejectAllIfMatch && ifMatch != null) {
            respond(ex, 412)
            return
        }
        if (config.honourIfMatch && ifMatch != null) {
            val tokens = ifMatch.split(",").map { it.trim() }
            val ok = existing != null && (ifMatch.trim() == "*" || tokens.any { it == currentEtag && !it.startsWith("W/") })
            if (!ok) {
                respond(ex, 412)
                return
            }
        }
        if (config.honourIfNoneMatch && ifNoneMatch != null) {
            val matches = existing != null && (ifNoneMatch.trim() == "*" || ifNoneMatch.split(",").any { it.trim() == currentEtag })
            if (matches) {
                respond(ex, 412)
                return
            }
        }
        files[name] = body
        if (name == VAULT) putSinceGet = true
        val headers = if (config.etagOnPut) mapOf("ETag" to etagOf(body)) else emptyMap()
        respond(ex, if (existing == null) 201 else 204, headers = headers)
    }

    private fun propfind(ex: HttpExchange, name: String) {
        config.propfindOverride?.let {
            respond(ex, 207, it.toByteArray(), mapOf("Content-Type" to "application/xml"))
            return
        }
        if (name.isEmpty()) {
            // Depth-1 listing of the collection: the collection itself plus every file.
            val sb = StringBuilder("""<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">""")
            sb.append("<D:response><D:href>/dav/</D:href></D:response>")
            for ((fileName, content) in files) {
                sb.append("<D:response><D:href>/dav/$fileName</D:href><D:propstat><D:prop><D:getetag>")
                sb.append(etagOf(content).replace("\"", "&quot;"))
                sb.append("</D:getetag></D:prop></D:propstat></D:response>")
            }
            sb.append("</D:multistatus>")
            respond(ex, 207, sb.toString().toByteArray(), mapOf("Content-Type" to "application/xml"))
            return
        }
        val bytes = files[name]
        if (bytes == null) {
            respond(ex, 404)
            return
        }
        val etag = etagOf(bytes).let { if (config.escapeQuotesInXml) it.replace("\"", "&quot;") else it }
        val xml = """<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:"><D:response><D:href>/dav/$name</D:href><D:propstat><D:prop><D:getetag>$etag</D:getetag></D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response></D:multistatus>"""
        respond(ex, 207, xml.toByteArray(), mapOf("Content-Type" to "application/xml"))
    }

    override fun close() {
        server.stop(0)
        executor.shutdownNow()
    }

    companion object {
        const val VAULT = "terminalmax.vault"
        const val LOCK = "terminalmax.lock"
    }
}
