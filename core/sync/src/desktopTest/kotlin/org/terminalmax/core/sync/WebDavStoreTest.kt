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
        assertEquals(
            ServerCapabilities(
                honoursIfMatch = true,
                acceptsMatchingIfMatch = true,
                honoursIfNoneMatchStar = true,
                honoursIfMatchOnDelete = true,
                etagChangesOnPut = true,
                putReturnsEtag = true,
                strongEtags = true,
            ),
            caps,
        )
        assertTrue(caps.supportsConditionalLocks)
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
    fun probeDetectsAServerThatRejectsEvenTheCorrectEtag() = runBlocking<Unit> {
        val s = server(Config(rejectAllIfMatch = true))
        val caps = store(s).probe()
        assertTrue(caps.honoursIfMatch, "a bogus ETag is rejected, so this alone would look fine")
        assertFalse(caps.acceptsMatchingIfMatch, "the correct ETag from GET must be accepted for the server to count")
        assertFalse(caps.supportsConditionalWrites)
        assertTrue(noScratchFilesLeft(s))
    }

    @Test
    fun probeDetectsAServerThatIgnoresIfMatchOnDelete() = runBlocking<Unit> {
        val s = server(Config(honourIfMatchOnDelete = false))
        val caps = store(s).probe()
        assertFalse(caps.honoursIfMatchOnDelete)
        assertTrue(caps.supportsConditionalWrites)
        assertFalse(caps.supportsConditionalLocks)
        assertTrue(noScratchFilesLeft(s))
    }

    @Test
    fun probeTreatsOverlongEtagsAsNotStrong() = runBlocking<Unit> {
        val s = server(Config(etagOverride = "\"" + "a".repeat(300) + "\""))
        val caps = store(s).probe()
        assertFalse(caps.strongEtags)
        assertFalse(caps.supportsConditionalWrites)
    }

    @Test
    fun probeSweepsStaleScratchFilesAndOnlyThose() = runBlocking<Unit> {
        val s = server()
        s.files["terminalmax.probe-0123456789abcdef"] = byteArrayOf(1)
        s.files["terminalmax.probe-short"] = byteArrayOf(2)
        s.files["notes.txt"] = byteArrayOf(3)
        s.files[FakeDavServer.VAULT] = byteArrayOf(4)
        store(s).probe()
        assertFalse(s.files.containsKey("terminalmax.probe-0123456789abcdef"))
        assertTrue(s.files.containsKey("terminalmax.probe-short"))
        assertTrue(s.files.containsKey("notes.txt"))
        assertContentEquals(byteArrayOf(4), s.files[FakeDavServer.VAULT])
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
    fun etagsThatCouldInjectHeadersOrAreNotStrongAreNeverSent() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        for (bad in listOf("\"a\r\nX-Evil: 1\"", "\"\u00e9\"", "\"a\"b\"", "\"" + "a".repeat(257) + "\"", "W/\"a\"", "")) {
            assertIs<WriteResult.Failed>(st.write(byteArrayOf(1), bad, false), "accepted: ${bad.length} chars")
            assertEquals(DeleteResult.Failed, st.deleteLock(bad))
        }
        assertTrue(s.log.none { it.method == "PUT" || it.method == "DELETE" })
    }

    @Test
    fun isStrongEtagAcceptsOnlyQuotedVisibleAsciiOfBoundedLength() {
        assertTrue(isStrongEtag("\"abc\""))
        assertTrue(isStrongEtag("\"" + "a".repeat(256) + "\""))
        assertFalse(isStrongEtag("\"" + "a".repeat(257) + "\""))
        assertFalse(isStrongEtag(null))
        assertFalse(isStrongEtag(""))
        assertFalse(isStrongEtag("\"\""))
        assertFalse(isStrongEtag("abc"))
        assertFalse(isStrongEtag("W/\"abc\""))
        assertFalse(isStrongEtag("\"a\"b\""))
        assertFalse(isStrongEtag("\"a b\""))
        assertFalse(isStrongEtag("\"a\r\nb\""))
        assertFalse(isStrongEtag("\"a\tb\""))
        assertFalse(isStrongEtag("\"\u00e9\""))
        assertFalse(isStrongEtag("\"\u007f\""))
        assertEquals("\"x\"", usableEtag("\"x\""))
        assertNull(usableEtag("W/\"x\""))
    }

    @Test
    fun anOverlongServerEtagIsReadButIsNotUsable() = runBlocking<Unit> {
        val s = server(Config(etagOverride = "\"" + "a".repeat(300) + "\""))
        s.files[FakeDavServer.VAULT] = byteArrayOf(1)
        val r = store(s).read()!!
        assertFalse(isStrongEtag(r.etag))
        assertNull(usableEtag(r.etag))
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
        assertIs<WriteResult.Written>(st.writeLock("lock".toByteArray(), ifMatchEtag = null, ifNoneMatch = true))
        assertEquals(WriteResult.PreconditionFailed, st.writeLock("again".toByteArray(), ifMatchEtag = null, ifNoneMatch = true))
        val read = st.readLock()!!
        assertEquals("lock", String(read.bytes))
        // A conditional replace with the ETag that was read succeeds, with a stale one it fails.
        assertEquals(WriteResult.PreconditionFailed, st.writeLock("x".toByteArray(), "\"stale\"", false))
        assertIs<WriteResult.Written>(st.writeLock("renewed".toByteArray(), read.etag, false))
        assertEquals(DeleteResult.Deleted, st.deleteLock(null))
        assertEquals(DeleteResult.Deleted, st.deleteLock(null)) // already gone is fine
        assertNull(st.readLock())
    }

    @Test
    fun conditionalLockDeleteOnlyDeletesTheLockThatWasRead() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        st.writeLock("one".toByteArray(), null, true)
        val read = st.readLock()!!
        // Somebody replaces the lock between our read and our delete.
        s.files[FakeDavServer.LOCK] = "two".toByteArray()
        assertEquals(DeleteResult.PreconditionFailed, st.deleteLock(read.etag))
        assertEquals("two", String(st.readLock()!!.bytes))
        assertEquals(DeleteResult.Deleted, st.deleteLock(st.readLock()!!.etag))
        assertNull(st.readLock())
    }

    @Test
    fun serverKeyBindsUrlAndAccountAndIgnoresTheTrailingSlash() {
        val s = server()
        val base = store(s)
        assertEquals(base.serverKey, WebDavStore(s.baseUrl.trimEnd('/'), "u", "other".toCharArray()).serverKey)
        assertTrue(base.serverKey != store(s, user = "someone").serverKey)
        assertTrue(base.serverKey != WebDavStore("http://127.0.0.1:${s.port}/dav2/", "u", "p".toCharArray()).serverKey)
        assertFalse(base.serverKey.contains("\"p\""), "the password must not be part of the key")
    }

    @Test
    fun theServerDateIsTrackedFromResponses() = runBlocking<Unit> {
        val s = server()
        val st = store(s)
        assertNull(st.lastServerDateMillis)
        st.read()
        val date = assertNotNull(st.lastServerDateMillis)
        assertTrue(kotlin.math.abs(date - System.currentTimeMillis()) < 5 * 60_000L)
    }

    @Test
    fun localhostIsReachedThroughTheLoopbackAddress() = runBlocking<Unit> {
        val s = server()
        val st = WebDavStore("http://localhost:${s.port}/dav/", "u", "p".toCharArray())
        s.files[FakeDavServer.VAULT] = byteArrayOf(7)
        assertContentEquals(byteArrayOf(7), st.read()!!.bytes)
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
        assertFailsWith<IllegalArgumentException> { WebDavStore("https://e.com/", "u", "p".toCharArray(), fileName = ".") }
        assertFailsWith<IllegalArgumentException> { WebDavStore("https://e.com/", "u", "p".toCharArray(), fileName = "..") }
        assertFailsWith<IllegalArgumentException> { WebDavStore("https://e.com/", "u", "p".toCharArray(), lockFileName = "..") }
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
    fun aRedirectToTheSameHostOnAnotherPortIsRefused() = runBlocking<Unit> {
        val seenByTarget = CopyOnWriteArrayList<String?>()
        val target = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        target.createContext("/") { ex ->
            seenByTarget += ex.requestHeaders.getFirst("Authorization")
            ex.sendResponseHeaders(200, -1)
            ex.close()
        }
        target.start()
        cleanup += AutoCloseable { target.stop(0) }
        val source = HttpServer.create(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 0)
        source.createContext("/") { ex ->
            ex.responseHeaders.add("Location", "http://127.0.0.1:${target.address.port}/dav/terminalmax.vault")
            ex.sendResponseHeaders(308, -1)
            ex.close()
        }
        source.start()
        cleanup += AutoCloseable { source.stop(0) }
        val st = WebDavStore("http://127.0.0.1:${source.address.port}/dav/", "u", "p".toCharArray())
        assertFailsWith<RemoteIoException> { st.read() }
        assertTrue(seenByTarget.isEmpty(), "a different port is a different origin: $seenByTarget")
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
    fun parserPicksTheEtagOfTheRequestedHrefFromAMultistatus() {
        val xml = """<D:multistatus xmlns:D="DAV:">
            <D:response><D:href>/dav/other.txt</D:href><D:propstat><D:prop><D:getetag>&quot;other&quot;</D:getetag></D:prop></D:propstat></D:response>
            <D:response><D:href>http://h/dav/terminalmax.vault</D:href><D:propstat><D:prop><D:getetag>&quot;vault&quot;</D:getetag></D:prop></D:propstat></D:response>
            </D:multistatus>"""
        assertEquals("\"vault\"", PropfindParser.extractEtag(xml, forHref = "terminalmax.vault"))
        assertEquals("\"other\"", PropfindParser.extractEtag(xml, forHref = "other.txt"))
        assertNull(PropfindParser.extractEtag(xml, forHref = "missing"))
        assertEquals("\"other\"", PropfindParser.extractEtag(xml)) // without a name: the first one
        assertEquals(listOf("/dav/other.txt", "http://h/dav/terminalmax.vault"), PropfindParser.extractHrefs(xml))
    }

    @Test
    fun hostileXmlIsScannedInLinearTime() {
        val hostile = listOf(
            "<D:getetag>".repeat(100_000),
            "<".repeat(1_000_000),
            "<a ".repeat(300_000),
            "<D:getetag>" + "x".repeat(1_000_000),
            "<D:response><D:href>/a</D:href>".repeat(50_000),
            "<!--" + "-".repeat(1_000_000),
            "&amp;".repeat(500_000),
            "<D:getetag>" + "&#".repeat(400_000) + "</D:getetag>",
        )
        for (xml in hostile) {
            val start = System.nanoTime()
            try {
                PropfindParser.extractEtag(xml)
                PropfindParser.extractHrefs(xml)
            } catch (e: XmlRejectedException) {
                // also an acceptable answer
            }
            val millis = (System.nanoTime() - start) / 1_000_000
            assertTrue(millis < 3_000, "took $millis ms for ${xml.take(16)}")
        }
    }

    @Test
    fun anOversizedPropfindAnswerIsRejectedWithoutBlockingTheProbe() = runBlocking<Unit> {
        val huge = "<D:multistatus xmlns:D=\"DAV:\">" + "<D:getetag>&quot;x&quot;</D:getetag>".repeat(100_000) + "</D:multistatus>"
        val s = server(Config(propfindOverride = huge))
        val start = System.nanoTime()
        val caps = store(s).probe()
        assertTrue((System.nanoTime() - start) / 1_000_000 < 20_000)
        assertTrue(caps.supportsConditionalWrites)
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
        val caps = store(s).probe() // the listing is rejected, the probe itself only uses GET ETags
        assertTrue(caps.supportsConditionalWrites)
        assertTrue(s.requests("PROPFIND").isNotEmpty())
        assertTrue(contacted.isEmpty(), "external entity was fetched: $contacted")
    }
}
