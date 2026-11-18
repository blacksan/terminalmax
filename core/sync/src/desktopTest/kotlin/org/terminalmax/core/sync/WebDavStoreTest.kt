// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import com.sun.net.httpserver.HttpServer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking
import org.terminalmax.core.sync.FakeDavServer.Config
import org.terminalmax.core.sync.FakeDavServer.EtagStyle

class WebDavStoreTest {
    private val cleanup = CopyOnWriteArrayList<AutoCloseable>()

    @AfterTest
    fun tearDown() {
        cleanup.forEach { runCatching { it.close() } }
    }

    private fun server(config: Config = Config()): FakeDavServer = FakeDavServer(config).also { cleanup += it }

    private fun store(server: FakeDavServer, user: String = "u", pass: String = "p") =
        WebDavStore(server.baseUrl, user, pass.toCharArray())

    private fun noScratchFilesLeft(server: FakeDavServer) =
        server.files.keys.none { it.startsWith("terminalmax.probe-") }

    // ------------------------------------------------------------------ probe

    @Test
    fun probeReportsAFullyCapableServerAndCleansUp() = runBlocking<Unit> {
        val s = server()
        val caps = store(s).probe()
        assertEquals(ServerCapabilities(true, true, true, true, true), caps)
        assertTrue(caps.supportsConditionalWrites)
        assertTrue(noScratchFilesLeft(s), "scratch file left behind: ${s.files.keys}")
        assertTrue(s.files.isEmpty())
        assertTrue(s.requests("DELETE").isNotEmpty())
    }

    @Test
    fun probeDetectsServerThatIgnoresPreconditions() = runBlocking<Unit> {
        val s = server(Config(honourIfMatch = false, honourIfNoneMatch = false))
        val caps = store(s).probe()
        assertFalse(caps.honoursIfMatch)
        assertFalse(caps.honoursIfNoneMatchStar)
        assertTrue(caps.etagChangesOnPut)
        assertTrue(caps.strongEtags)
        assertFalse(caps.supportsConditionalWrites)
        assertTrue(noScratchFilesLeft(s))
    }

    @Test
    fun probeDetectsPartialPreconditionSupport() = runBlocking<Unit> {
        val onlyIfMatch = store(server(Config(honourIfNoneMatch = false))).probe()
        assertTrue(onlyIfMatch.honoursIfMatch)
        assertFalse(onlyIfMatch.honoursIfNoneMatchStar)
        val onlyIfNone = store(server(Config(honourIfMatch = false))).probe()
        assertFalse(onlyIfNone.honoursIfMatch)
        assertTrue(onlyIfNone.honoursIfNoneMatchStar)
    }

    @Test
    fun probeDetectsMissingEtagOnPut() = runBlocking<Unit> {
        val s = server(Config(etagOnPut = false))
        val caps = store(s).probe()
        assertFalse(caps.putReturnsEtag)
        assertTrue(caps.honoursIfMatch)
        assertTrue(caps.etagChangesOnPut)
        assertTrue(caps.strongEtags)
        assertTrue(noScratchFilesLeft(s))
    }

    @Test
    fun probeDetectsWeakEtags() = runBlocking<Unit> {
        val s = server(Config(etagStyle = EtagStyle.WEAK))
        val caps = store(s).probe()
        assertFalse(caps.strongEtags)
        assertTrue(caps.etagChangesOnPut)
        assertFalse(caps.supportsConditionalWrites)
        assertTrue(noScratchFilesLeft(s))
    }

    @Test
    fun probeDetectsEtagThatDoesNotChangeForSameSizeWrites() = runBlocking<Unit> {
        val s = server(Config(etagStyle = EtagStyle.MTIME_SIZE))
        val caps = store(s).probe()
        assertFalse(caps.etagChangesOnPut)
        assertTrue(caps.strongEtags)
        assertFalse(caps.supportsConditionalWrites)
        assertTrue(noScratchFilesLeft(s))
    }

    @Test
    fun probeNeverTouchesTheVaultFile() = runBlocking<Unit> {
        val s = server()
        s.files[FakeDavServer.VAULT] = byteArrayOf(1, 2, 3)
        store(s).probe()
        assertContentEquals(byteArrayOf(1, 2, 3), s.files[FakeDavServer.VAULT])
        assertTrue(s.log.none { it.path.endsWith(FakeDavServer.VAULT) })
    }

    @Test
    fun probeCreatesTheCollectionWhenMissing() = runBlocking<Unit> {
        val s = server(Config(collectionExists = false))
        val caps = store(s).probe()
        assertTrue(caps.supportsConditionalWrites)
        assertTrue(s.requests("MKCOL").isNotEmpty())
    }

    // ------------------------------------------------------------------ read / write

    @Test
    fun readReturnsNullWhenMissingAndBytesWithEtagWhenPresent() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        assertNull(st.read())
        val w = st.write(byteArrayOf(9, 8, 7), ifMatchEtag = null, ifNoneMatch = true)
        assertIs<WriteResult.Written>(w)
        val r = assertNotNull(st.read())
        assertContentEquals(byteArrayOf(9, 8, 7), r.bytes)
        assertTrue(isStrongEtag(r.etag))
    }

    @Test
    fun conditionalWritesAreHonouredAgainstACooperativeServer() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        st.write(byteArrayOf(1), null, true)
        // create-only on an existing file
        assertEquals(WriteResult.PreconditionFailed, st.write(byteArrayOf(2), null, true))
        val etag = st.read()!!.etag
        // stale If-Match
        assertEquals(WriteResult.PreconditionFailed, st.write(byteArrayOf(3), "\"stale\"", false))
        // matching If-Match
        assertIs<WriteResult.Written>(st.write(byteArrayOf(4), etag, false))
        assertContentEquals(byteArrayOf(4), st.read()!!.bytes)
        // If-Match on a missing file
        s.files.clear()
        assertEquals(WriteResult.PreconditionFailed, st.write(byteArrayOf(5), "\"x\"", false))
    }

    @Test
    fun weakEtagsAreNeverSentInIfMatch() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        val result = st.write(byteArrayOf(1), "W/\"abc\"", false)
        assertIs<WriteResult.Failed>(result)
        assertTrue(s.log.none { it.method == "PUT" }, "request must not be sent")
        assertIs<WriteResult.Failed>(st.write(byteArrayOf(1), "abc", false))
    }

    @Test
    fun mkcolIsAttemptedWhenTheCollectionIsMissing() = runBlocking<Unit> {
        val s = server(Config(collectionExists = false))
        val st = store(s)
        assertIs<WriteResult.Written>(st.write(byteArrayOf(1), null, true))
        assertEquals(1, s.requests("MKCOL").size)
        assertContentEquals(byteArrayOf(1), s.files[FakeDavServer.VAULT])
    }

    @Test
    fun lockFileOperationsWork() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        assertNull(st.readLock())
        assertIs<WriteResult.Written>(st.writeLock("lock".toByteArray(), ifNoneMatch = true))
        assertEquals(WriteResult.PreconditionFailed, st.writeLock("again".toByteArray(), ifNoneMatch = true))
        assertEquals("lock", String(st.readLock()!!.bytes))
        assertTrue(st.deleteLock())
        assertTrue(st.deleteLock()) // already gone is fine
        assertNull(st.readLock())
    }

    @Test
    fun responseBodiesAreCapped() = runBlocking<Unit> {
        val s = server()
        s.files[FakeDavServer.VAULT] = ByteArray(5000)
        val capped = WebDavStore(s.baseUrl, "u", "p".toCharArray(), maxResponseBytes = 1000)
        assertFailsWith<RemoteIoException> { capped.read() }
        val ok = WebDavStore(s.baseUrl, "u", "p".toCharArray(), maxResponseBytes = 5000)
        assertEquals(5000, ok.read()!!.bytes.size)
    }

    @Test
    fun networkFailureSurfacesAsRemoteIoException() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        s.close()
        assertFailsWith<RemoteIoException> { st.read() }
        Unit
    }

    // ------------------------------------------------------------------ authentication and transport security

    @Test
    fun basicAuthIsSentPreemptivelyAndWrongCredentialsAreRejected() = runBlocking<Unit> {
        val s = server(Config(credentials = "alice" to "s3cret"))
        val good = store(s, "alice", "s3cret")
        assertNull(good.read())
        assertNotNull(s.log.first().authorization, "first request must already carry credentials")
        assertTrue(s.log.first().authorization!!.startsWith("Basic "))
        assertFailsWith<RemoteAuthException> { store(s, "alice", "wrong").read() }
        assertFailsWith<RemoteAuthException> { store(s, "alice", "wrong").probe() }
    }

    @Test
    fun passwordArrayIsNotModified() {
        val s = server()
        val p = "pw".toCharArray()
        WebDavStore(s.baseUrl, "u", p)
        assertContentEquals("pw".toCharArray(), p)
    }

    @Test
    fun plainHttpToNonLocalHostsIsRefused() {
        assertFailsWith<IllegalArgumentException> { WebDavStore("http://dav.example.com/dav/", "u", "p".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { WebDavStore("http://192.0.2.10/dav/", "u", "p".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { WebDavStore("http://localhost.example.com/dav/", "u", "p".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { WebDavStore("not a url", "u", "p".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { WebDavStore("ftp://example.com/", "u", "p".toCharArray()) }
        assertFailsWith<IllegalArgumentException> { WebDavStore("https://user:pw@example.com/", "u", "p".toCharArray()) }
        // Allowed: HTTPS, loopback HTTP, explicit opt-in.
        WebDavStore("https://dav.example.com/dav", "u", "p".toCharArray())
        WebDavStore("http://localhost:8080/dav/", "u", "p".toCharArray())
        WebDavStore("http://127.0.0.1/dav/", "u", "p".toCharArray())
        WebDavStore("http://[::1]:8080/dav/", "u", "p".toCharArray())
        WebDavStore("http://dav.example.com/dav/", "u", "p".toCharArray(), allowInsecureHttp = true)
    }

    @Test
    fun invalidFileNamesAreRejected() {
        assertFailsWith<IllegalArgumentException> { WebDavStore("https://e.com/", "u", "p".toCharArray(), fileName = "../x") }
        assertFailsWith<IllegalArgumentException> { WebDavStore("https://e.com/", "u", "p".toCharArray(), fileName = "a/b") }
    }

    @Test
    fun credentialsAreNeverSentToARedirectTargetOnAnotherHost() = runBlocking<Unit> {
        val seenByTarget = CopyOnWriteArrayList<String?>()
        val target = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        target.createContext("/") { ex ->
            seenByTarget += ex.requestHeaders.getFirst("Authorization")
            ex.sendResponseHeaders(200, -1)
            ex.close()
        }
        target.start()
        cleanup += AutoCloseable { target.stop(0) }

        val seenBySource = CopyOnWriteArrayList<String?>()
        val source = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        source.createContext("/") { ex ->
            seenBySource += ex.requestHeaders.getFirst("Authorization")
            // Same machine but a different host name and port: a different origin.
            ex.responseHeaders.add("Location", "http://localhost:${target.address.port}/dav/terminalmax.vault")
            ex.sendResponseHeaders(307, -1)
            ex.close()
        }
        source.start()
        cleanup += AutoCloseable { source.stop(0) }

        val st = WebDavStore("http://127.0.0.1:${source.address.port}/dav/", "u", "p".toCharArray())
        assertFailsWith<RemoteIoException> { st.read() }
        assertFailsWith<RemoteIoException> { st.write(byteArrayOf(1), null, false) }
        assertTrue(seenBySource.isNotEmpty() && seenBySource.all { it != null })
        assertTrue(seenByTarget.isEmpty(), "redirect target was contacted: $seenByTarget")
    }

    @Test
    fun sameOriginTemporaryRedirectsAreFollowed() = runBlocking<Unit> {
        val seen = CopyOnWriteArrayList<Pair<String, String?>>()
        val srv = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        srv.createContext("/") { ex ->
            seen += ex.requestURI.path to ex.requestHeaders.getFirst("Authorization")
            if (ex.requestURI.path == "/dav/terminalmax.vault") {
                ex.responseHeaders.add("Location", "/dav/moved.vault")
                ex.sendResponseHeaders(307, -1)
            } else {
                val body = byteArrayOf(5, 5)
                ex.responseHeaders.add("ETag", "\"e1\"")
                ex.sendResponseHeaders(200, body.size.toLong())
                ex.responseBody.use { it.write(body) }
            }
            ex.close()
        }
        srv.start()
        cleanup += AutoCloseable { srv.stop(0) }

        val st = WebDavStore("http://127.0.0.1:${srv.address.port}/dav/", "u", "p".toCharArray())
        val file = st.read()!!
        assertContentEquals(byteArrayOf(5, 5), file.bytes)
        assertEquals(listOf("/dav/terminalmax.vault", "/dav/moved.vault"), seen.map { it.first })
        assertTrue(seen.all { it.second != null })
    }

    // ------------------------------------------------------------------ XML handling

    @Test
    fun parserExtractsEtagsFromCommonShapes() {
        assertEquals("\"abc\"", PropfindParser.extractEtag("<D:multistatus xmlns:D=\"DAV:\"><D:getetag>\"abc\"</D:getetag></D:multistatus>"))
        assertEquals("\"abc\"", PropfindParser.extractEtag("<d:getetag>&quot;abc&quot;</d:getetag>"))
        assertEquals("W/\"abc\"", PropfindParser.extractEtag("<getetag xmlns=\"DAV:\">W/&quot;abc&quot;</getetag>"))
        assertEquals("\"a&b\"", PropfindParser.extractEtag("<ns0:GETETAG>\"a&amp;b\"</ns0:GETETAG>"))
        assertEquals("\"x\"", PropfindParser.extractEtag("<D:getetag><![CDATA[\"x\"]]></D:getetag>"))
        assertEquals("\"A\"", PropfindParser.extractEtag("<D:getetag>&#34;A&#x22;</D:getetag>"))
        assertEquals("\"second\"", PropfindParser.extractEtag("<D:getetag/><D:getetag>\"second\"</D:getetag>"))
        assertNull(PropfindParser.extractEtag("<D:getetag/>"))
        assertNull(PropfindParser.extractEtag("<D:getetag></D:getetag>"))
        assertNull(PropfindParser.extractEtag("<D:multistatus/>"))
        assertNull(PropfindParser.extractEtag("garbage <<<>>>"))
    }

    @Test
    fun parserRejectsDoctypeAndEntityDeclarations() {
        val xxe = """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:1/x">]><D:getetag>&x;</D:getetag>"""
        assertFailsWith<XmlRejectedException> { PropfindParser.extractEtag(xxe) }
        assertFailsWith<XmlRejectedException> { PropfindParser.extractEtag("<!doctype a><a/>") }
        assertFailsWith<XmlRejectedException> { PropfindParser.extractEtag("<!ENTITY a \"b\">") }
        // Undeclared references are never expanded.
        assertEquals("&x;", PropfindParser.extractEtag("<D:getetag>&x;</D:getetag>"))
    }

    @Test
    fun serverSuppliedXxeIsNotFollowedAndProbeStillCompletes() = runBlocking<Unit> {
        val contacted = CopyOnWriteArrayList<String>()
        val victim = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        victim.createContext("/") { ex ->
            contacted += ex.requestURI.path
            ex.sendResponseHeaders(200, -1)
            ex.close()
        }
        victim.start()
        cleanup += AutoCloseable { victim.stop(0) }

        val xxe = """<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://127.0.0.1:${victim.address.port}/xxe">]>
            <D:multistatus xmlns:D="DAV:"><D:getetag>&x;</D:getetag></D:multistatus>""".trimIndent()
        val s = server(Config(propfindOverride = xxe))
        val caps = store(s).probe() // PROPFIND is rejected, the GET ETag header is used instead
        assertTrue(caps.supportsConditionalWrites)
        assertTrue(s.requests("PROPFIND").isNotEmpty())
        assertTrue(contacted.isEmpty(), "external entity was fetched: $contacted")
    }
}
