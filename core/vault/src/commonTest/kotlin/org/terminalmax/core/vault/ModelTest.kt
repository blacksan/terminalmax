// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.vault

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

class ModelTest {
    private val future = """
        {
          "schemaVersion": 1,
          "vaultId": "v",
          "revision": 7,
          "records": [
            {"id":"1","type":"Host","revision":2,"deviceId":"A","updatedAtEpochMs":5,"deleted":false,
             "payload":{"label":"L","address":"h","port":22,"username":"u","algorithmProfile":"Modern","futureField":{"x":[1,2,3]}},
             "recordLevelFuture":"keep-me"},
            {"id":"2","type":"Gizmo","revision":1,"deviceId":"B","updatedAtEpochMs":6,"deleted":false,
             "payload":{"anything":true}}
          ],
          "history": []
        }
    """.trimIndent()

    @Test
    fun unknownTypesAndFieldsRoundTripUnchanged() {
        val decoded = VaultJson.decodeContent(future)
        assertEquals(RecordType.Unknown, decoded.records[1].type)
        assertEquals("Gizmo", decoded.records[1].wireTypeName)
        val encoded = VaultJson.encodeContent(decoded)
        assertEquals(Json.parseToJsonElement(future), Json.parseToJsonElement(encoded))
        assertEquals(decoded, VaultJson.decodeContent(encoded))
    }

    @Test
    fun typedPayloadDecodeIgnoresUnknownFields() {
        val decoded = VaultJson.decodeContent(future)
        val host = Payloads.host(decoded.records[0].payload)
        assertEquals("h", host.address)
        assertEquals(AlgorithmProfiles.MODERN, host.algorithmProfile)
        assertNull(host.identityId)
    }

    @Test
    fun typedUpsertKeepsUnknownPayloadFields() {
        val decoded = VaultJson.decodeContent(future)
        val editor = VaultEditor(decoded, "C")
        val host = Payloads.host(decoded.records[0].payload).copy(label = "renamed")
        val updated = editor.upsertHost(host, id = "1")
        assertEquals(3L, updated.revision)
        assertEquals("C", updated.deviceId)
        assertEquals(JsonPrimitive("renamed"), updated.payload["label"])
        assertNotNull(updated.payload["futureField"])
        assertEquals(JsonPrimitive("keep-me"), updated.extra["recordLevelFuture"])
    }

    @Test
    fun typedUpsertRemovesClearedOptionalFields() {
        val editor = VaultEditor(VaultContent.empty("v"), "A")
        val r = editor.upsertHost(HostPayload("L", "h", 22, "u", identityId = "i1"))
        assertEquals(JsonPrimitive("i1"), r.payload["identityId"])
        val r2 = editor.upsertHost(HostPayload("L", "h", 22, "u", identityId = null), id = r.id)
        assertFalse(r2.payload.containsKey("identityId"))
    }

    @Test
    fun upsertAndDeleteBumpRevisions() {
        val editor = VaultEditor(VaultContent.empty("v"), "A", newId = { "fixed" })
        val created = editor.upsert(RecordType.Snippet, null, JsonObject(mapOf("t" to JsonPrimitive("x"))))
        assertEquals("fixed", created.id)
        assertEquals(1L, created.revision)
        assertEquals(1L, editor.content.revision)
        val edited = editor.upsert(RecordType.Snippet, "fixed", JsonObject(mapOf("t" to JsonPrimitive("y"))))
        assertEquals(2L, edited.revision)
        assertEquals(2L, editor.content.revision)
        val tomb = editor.delete("fixed")!!
        assertTrue(tomb.deleted)
        assertEquals(3L, tomb.revision)
        assertTrue(tomb.payload.isEmpty())
        assertEquals(3L, editor.content.revision)
        assertEquals(1, editor.content.records.size)
        assertNull(editor.delete("missing"))
    }

    @Test
    fun allPayloadTypesRoundTrip() {
        val editor = VaultEditor(VaultContent.empty("v"), "A")
        editor.upsertHost(HostPayload("h", "10.0.0.1", 2222, "admin", "i", "w", AlgorithmProfiles.LEGACY, "+ct"))
        editor.upsertIdentity(IdentityPayload("id", "root", "pw", null))
        editor.upsertPrivateKey(PrivateKeyPayload("k", "PEM", "pass"))
        editor.upsertWireGuardProfile(WireGuardProfilePayload("wg", "[Interface]"))
        editor.upsertKnownHost(KnownHostPayload("h", 22, "ssh-ed25519", "SHA256:abc", "AAAA"))
        editor.upsertSnippet(SnippetPayload("s", "ls"))
        val decoded = VaultJson.decodeContent(VaultJson.encodeContent(editor.content))
        assertEquals(editor.content, decoded)
        val host = decoded.records.first { it.type == RecordType.Host }
        assertEquals("+ct", Payloads.host(host.payload).routerOsConsoleOptions)
        assertTrue(host.payload.jsonObject.containsKey("port"))
    }

    @Test
    fun randomUuidLooksLikeVersion4() {
        val id = randomUuidV4()
        assertEquals(36, id.length)
        assertEquals('4', id[14])
        assertTrue(id[19] in "89ab")
    }
}
