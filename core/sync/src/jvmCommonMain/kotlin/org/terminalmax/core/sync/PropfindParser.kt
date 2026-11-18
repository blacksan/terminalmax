// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

/** Thrown for XML that declares a DTD or entities; such documents are never interpreted. */
class XmlRejectedException(message: String) : RemoteIoException(message)

/**
 * Extracts the `getetag` value from a PROPFIND multistatus body.
 *
 * Deliberately not a real XML parser. `javax.xml.parsers` and Android's `XmlPullParser` differ (Android's
 * DocumentBuilderFactory rejects the Xerces security features that make the JDK parser XXE-safe, and
 * XmlPullParser does not exist on the desktop JVM), so one tolerant scanner is used on both. It never resolves
 * entities, DTDs or external references, so XXE and entity-expansion attacks have nothing to act on. Documents
 * containing `<!DOCTYPE` or `<!ENTITY` are rejected outright. Namespace prefixes are accepted but not resolved.
 */
object PropfindParser {
    private val etagElement = Regex(
        "<(?:[A-Za-z_][\\w.\\-]*:)?getetag(?:\\s[^>]*)?>(.*?)</(?:[A-Za-z_][\\w.\\-]*:)?getetag\\s*>",
        setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL),
    )
    private val reference = Regex("&(#x[0-9a-fA-F]{1,6}|#[0-9]{1,7}|quot|amp|lt|gt|apos);")

    /** @throws XmlRejectedException when the document has a DTD or entity declaration */
    fun extractEtag(xml: String): String? {
        if (xml.contains("<!DOCTYPE", ignoreCase = true) || xml.contains("<!ENTITY", ignoreCase = true)) {
            throw XmlRejectedException("XML with a DTD or entity declaration was rejected")
        }
        for (match in etagElement.findAll(xml)) {
            val value = unescape(stripCdata(match.groupValues[1].trim())).trim()
            if (value.isNotEmpty()) return value
        }
        return null
    }

    private fun stripCdata(text: String): String =
        if (text.startsWith("<![CDATA[") && text.endsWith("]]>")) text.substring(9, text.length - 3) else text

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
