// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

/** Thrown for XML that declares a DTD or entities; such documents are never interpreted. */
class XmlRejectedException(message: String) : RemoteIoException(message)

/**
 * Extracts `href` and `getetag` values from a PROPFIND multistatus body.
 *
 * Deliberately not a real XML parser. `javax.xml.parsers` and Android's `XmlPullParser` differ (Android's
 * DocumentBuilderFactory rejects the Xerces security features that make the JDK parser XXE-safe, and
 * XmlPullParser does not exist on the desktop JVM), so one tolerant scanner is used on both. It never resolves
 * entities, DTDs or external references, so XXE and entity-expansion attacks have nothing to act on. Documents
 * containing `<!DOCTYPE` or `<!ENTITY` are rejected outright. Namespace prefixes are accepted but not resolved.
 *
 * The scanner makes one left-to-right pass: every tag is bounded to [MAX_TAG_CHARS] characters and every text value
 * to [MAX_TEXT_CHARS], and no step ever rescans earlier input, so hostile input costs time linear in its size
 * (there are no backtracking regular expressions).
 */
object PropfindParser {
    private const val MAX_TAG_CHARS = 1024
    private const val MAX_TEXT_CHARS = 1024
    private const val MAX_ENTRIES = 1024

    /** One `response` element: its `href` and the first non-empty `getetag` it carries (either may be null). */
    data class Entry(val href: String?, val etag: String?)

    private val reference = Regex("&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|quot|amp|lt|gt|apos);")

    /**
     * The `getetag` of the response whose `href` names [forHref] (compared by its last path segment), or, when
     * [forHref] is null, the first non-empty `getetag` in the document.
     *
     * @throws XmlRejectedException when the document has a DTD or entity declaration
     */
    fun extractEtag(xml: String, forHref: String? = null): String? {
        val entries = extractEntries(xml)
        return if (forHref == null) {
            entries.firstOrNull { it.etag != null }?.etag
        } else {
            entries.firstOrNull { it.etag != null && it.href != null && lastSegment(it.href) == forHref }?.etag
        }
    }

    /** All `href` values (document order), for listing a collection. */
    fun extractHrefs(xml: String): List<String> = extractEntries(xml).mapNotNull { it.href }

    /** @throws XmlRejectedException when the document has a DTD or entity declaration */
    fun extractEntries(xml: String): List<Entry> {
        if (xml.contains("<!DOCTYPE", ignoreCase = true) || xml.contains("<!ENTITY", ignoreCase = true)) {
            throw XmlRejectedException("XML with a DTD or entity declaration was rejected")
        }
        val entries = ArrayList<Entry>()
        var inResponse = false
        var href: String? = null
        var etag: String? = null
        var i = 0
        val n = xml.length
        while (i < n && entries.size < MAX_ENTRIES) {
            val lt = xml.indexOf('<', i)
            if (lt < 0) break
            // A comment: skip it, or stop for good when it never ends.
            if (xml.startsWith("<!--", lt)) {
                val end = xml.indexOf("-->", lt + 4)
                if (end < 0) break
                i = end + 3
                continue
            }
            // The tag must close with '>' within MAX_TAG_CHARS without another '<' in between.
            var gt = -1
            var j = lt + 1
            val limit = minOf(n, lt + 1 + MAX_TAG_CHARS)
            while (j < limit) {
                val c = xml[j]
                if (c == '>') {
                    gt = j
                    break
                }
                if (c == '<') break
                j++
            }
            if (gt < 0) {
                i = lt + 1
                continue
            }
            i = gt + 1
            val body = xml.substring(lt + 1, gt)
            if (body.isEmpty() || body[0] == '!' || body[0] == '?') continue
            val closing = body[0] == '/'
            val selfClosing = body.endsWith("/")
            val name = localName(body, closing)
            when (name) {
                "response" -> {
                    if (closing) {
                        if (inResponse && (href != null || etag != null)) entries += Entry(href, etag)
                        inResponse = false
                        href = null
                        etag = null
                    } else if (!selfClosing) {
                        inResponse = true
                        href = null
                        etag = null
                    }
                }
                "href", "getetag" -> if (!closing && !selfClosing) {
                    // An unterminated CDATA section can never end later either: stop for good (keeps the scan linear).
                    if (xml.startsWith("<![CDATA[", i) && xml.indexOf("]]>", i + 9) < 0) break
                    val read = readText(xml, i)
                    if (read != null) {
                        i = read.second
                        val value = unescape(read.first.trim()).trim()
                        if (value.isNotEmpty()) {
                            if (name == "href") {
                                if (inResponse) {
                                    if (href == null) href = value
                                } else {
                                    entries += Entry(value, null)
                                }
                            } else if (inResponse) {
                                if (etag == null) etag = value
                            } else {
                                entries += Entry(null, value)
                            }
                        }
                    }
                }
            }
        }
        return entries
    }

    /** Lower-case local name (no namespace prefix) of the element a tag body describes. */
    private fun localName(body: String, closing: Boolean): String {
        var start = if (closing) 1 else 0
        var end = start
        while (end < body.length) {
            val c = body[end]
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '/') break
            end++
        }
        val colon = body.lastIndexOf(':', end - 1)
        if (colon >= start) start = colon + 1
        return if (start < end) body.substring(start, end).lowercase() else ""
    }

    /**
     * Text content starting at [from]: plain text up to the next '<', or one CDATA section. Returns the text and
     * the index to continue at, or null when the value is longer than [MAX_TEXT_CHARS] or not terminated.
     */
    private fun readText(xml: String, from: Int): Pair<String, Int>? {
        if (xml.startsWith("<![CDATA[", from)) {
            val end = xml.indexOf("]]>", from + 9)
            if (end < 0 || end - (from + 9) > MAX_TEXT_CHARS) return null
            return xml.substring(from + 9, end) to end + 3
        }
        val next = xml.indexOf('<', from)
        if (next < 0 || next - from > MAX_TEXT_CHARS) return null
        return xml.substring(from, next) to next
    }

    private fun lastSegment(href: String): String = href.trimEnd('/').substringAfterLast('/')

    /** Resolves only the five predefined entities and numeric character references. */
    private fun unescape(text: String): String = reference.replace(text) { m ->
        when (val ref = m.groupValues[1]) {
            "quot" -> "\""
            "amp" -> "&"
            "lt" -> "<"
            "gt" -> ">"
            "apos" -> "'"
            else -> {
                val code = if (ref.startsWith("#x")) ref.substring(2).toIntOrNull(16) else ref.substring(1).toIntOrNull()
                if (code != null && code in 0x20..0x10FFFF) String(Character.toChars(code)) else m.value
            }
        }
    }
}
