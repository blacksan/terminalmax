// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.core.sync

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/**
 * Content of `terminalmax.lock`: who holds the lease, a random token to verify ownership, and its expiry
 * ([expiresAtEpochMs] is on the server's clock whenever the server sends a `Date` header).
 */
internal data class LockInfo(val deviceId: String, val token: String, val expiresAtEpochMs: Long)

internal object LockFile {
    private const val MAX_BYTES = 4096

    fun encode(info: LockInfo): ByteArray =
        JsonObject(
            mapOf(
                "deviceId" to JsonPrimitive(info.deviceId),
                "token" to JsonPrimitive(info.token),
                "expiresAtEpochMs" to JsonPrimitive(info.expiresAtEpochMs),
            ),
        ).toString().encodeToByteArray()

    /** Null for anything that is not a well-formed lock file (such locks are treated as stale). */
    fun decode(bytes: ByteArray): LockInfo? {
        if (bytes.size > MAX_BYTES) return null
        return try {
            val o = Json.parseToJsonElement(bytes.decodeToString()).jsonObject
            LockInfo(
                deviceId = o.getValue("deviceId").jsonPrimitive.content,
                token = o.getValue("token").jsonPrimitive.content,
                expiresAtEpochMs = o.getValue("expiresAtEpochMs").jsonPrimitive.long,
            )
        } catch (e: Exception) {
            null
        }
    }
}
