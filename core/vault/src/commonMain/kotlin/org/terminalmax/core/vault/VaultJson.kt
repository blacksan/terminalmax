// SPDX-License-Identifier: GPL-3.0-or-later
@file:OptIn(ExperimentalSerializationApi::class)

package org.terminalmax.core.vault

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.long

/** Shared JSON configuration for vault content. Unknown keys are tolerated (and preserved where it matters). */
object VaultJson {
    val json: Json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }

    val emptyObject: JsonObject = JsonObject(emptyMap())

    fun encodeContent(content: VaultContent): String = json.encodeToString(VaultContent.serializer(), content)

    fun decodeContent(text: String): VaultContent = json.decodeFromString(VaultContent.serializer(), text)

    /** Content JSON as it is sealed in a v2 file: the content plus the `keyEpoch` that binds it to its header. */
    internal fun encodeContentWithEpoch(content: VaultContent, keyEpoch: Long): String {
        val tree = json.encodeToJsonElement(VaultContent.serializer(), content).jsonObject
        val out = LinkedHashMap<String, JsonElement>(tree)
        out["keyEpoch"] = JsonPrimitive(keyEpoch)
        return JsonObject(out).toString()
    }

    /** Inverse of [encodeContentWithEpoch]; throws a [SerializationException] or [IllegalArgumentException]. */
    internal fun decodeContentWithEpoch(text: String): Pair<VaultContent, Long> {
        val tree = json.parseToJsonElement(text).jsonObject
        val epoch = tree["keyEpoch"] as? JsonPrimitive
        if (epoch == null || epoch.isString) throw SerializationException("Missing keyEpoch")
        val rest = LinkedHashMap<String, JsonElement>(tree)
        rest.remove("keyEpoch")
        return json.decodeFromJsonElement(VaultContent.serializer(), JsonObject(rest)) to epoch.long
    }

    internal fun <T> encodePayload(serializer: kotlinx.serialization.KSerializer<T>, value: T): JsonObject =
        json.encodeToJsonElement(serializer, value).jsonObject

    internal fun <T> decodePayload(serializer: kotlinx.serialization.KSerializer<T>, payload: JsonObject): T =
        json.decodeFromJsonElement(serializer, payload)
}
