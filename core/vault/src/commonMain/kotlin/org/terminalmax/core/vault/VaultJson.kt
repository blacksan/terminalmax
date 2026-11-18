// SPDX-License-Identifier: GPL-3.0-or-later
@file:OptIn(ExperimentalSerializationApi::class)

package org.terminalmax.core.vault

import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

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

    internal fun <T> encodePayload(serializer: kotlinx.serialization.KSerializer<T>, value: T): JsonObject =
        json.encodeToJsonElement(serializer, value).jsonObject

    internal fun <T> decodePayload(serializer: kotlinx.serialization.KSerializer<T>, payload: JsonObject): T =
        json.decodeFromJsonElement(serializer, payload)
}
