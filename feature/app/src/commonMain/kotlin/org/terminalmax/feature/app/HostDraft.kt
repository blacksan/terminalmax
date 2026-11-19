// SPDX-License-Identifier: GPL-3.0-or-later
package org.terminalmax.feature.app

enum class AuthKind { Password, Key }

enum class HostField { Label, Address, Port, Username, Password, Key, Options }

/**
 * What the host editor edits. Secrets are never loaded back into a draft: [password], [privateKeyPem] and
 * [passphrase] stay empty when editing, and [hasStoredPassword] / [hasStoredKey] say that something is stored
 * (leave the field empty to keep it).
 */
data class HostDraft(
    val id: String? = null,
    val label: String = "",
    val address: String = "",
    val port: String = "22",
    val username: String = "",
    val auth: AuthKind = AuthKind.Password,
    val password: String = "",
    val privateKeyPem: String = "",
    val passphrase: String = "",
    val wireGuardProfileId: String? = null,
    val legacy: Boolean = false,
    val consoleOptions: String = "",
    val hasStoredPassword: Boolean = false,
    val hasStoredKey: Boolean = false,
) {
    override fun toString(): String = "HostDraft(id=$id, label=$label)"
}

/** True for a dotted IPv4 or a plain IPv6 literal (no brackets, no zone id). */
fun isIpLiteral(value: String): Boolean = isIpv4(value) || isIpv6(value)

private fun isIpv4(value: String): Boolean {
    val parts = value.split('.')
    if (parts.size != 4) return false
    return parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all { it in '0'..'9' } && p.toInt() in 0..255 }
}

private fun isIpv6(value: String): Boolean {
    if (!value.contains(':')) return false
    if (value.any { !(it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.') }) return false
    if (value.count { it == ':' } < 2) return false
    if (value.indexOf("::") != value.lastIndexOf("::")) return false
    if (value.contains(":::")) return false
    return true
}

private val CONSOLE_OPTIONS = Regex("^\\+[A-Za-z0-9+\\-]{0,32}$")

/** RouterOS console options are appended to the user name (for example `+ct80w`); a missing leading '+' is added. */
fun normalizeConsoleOptions(raw: String): String {
    val t = raw.trim()
    if (t.isEmpty()) return ""
    return if (t.startsWith("+")) t else "+$t"
}

/** Field errors of [draft]; empty means it can be saved. */
fun validateHostDraft(draft: HostDraft): Map<HostField, String> {
    val errors = LinkedHashMap<HostField, String>()
    if (draft.label.isBlank()) errors[HostField.Label] = "Give the host a name."
    val address = draft.address.trim()
    when {
        address.isEmpty() -> errors[HostField.Address] = "Enter a host name or IP address."
        address.any { it.isWhitespace() } -> errors[HostField.Address] = "The address must not contain spaces."
        draft.wireGuardProfileId != null && !isIpLiteral(address) ->
            errors[HostField.Address] = "With a WireGuard profile the address must be an IP address (IPv4 or IPv6), not a name."
    }
    val port = draft.port.trim().toIntOrNull()
    if (port == null || port !in 1..65535) errors[HostField.Port] = "Port must be between 1 and 65535."
    if (draft.username.isBlank()) errors[HostField.Username] = "Enter the user name."
    if (draft.auth == AuthKind.Key) {
        val pem = draft.privateKeyPem
        if (pem.isBlank() && !draft.hasStoredKey) {
            errors[HostField.Key] = "Paste the private key."
        } else if (pem.isNotBlank() && !pem.contains("PRIVATE KEY")) {
            errors[HostField.Key] = "This does not look like a private key (expected an OpenSSH or PEM block)."
        }
    }
    val options = normalizeConsoleOptions(draft.consoleOptions)
    if (options.isNotEmpty() && !CONSOLE_OPTIONS.matches(options)) {
        errors[HostField.Options] = "Console options may only contain letters, digits, '+' and '-', for example +ct80w."
    }
    return errors
}

enum class PasswordStrength { TooShort, Weak, Fair, Strong }

/** A rough, local-only strength estimate for the vault password (length and character variety). */
fun passwordStrength(password: String): PasswordStrength {
    if (password.length < MIN_VAULT_PASSWORD) return PasswordStrength.TooShort
    var classes = 0
    if (password.any { it.isLowerCase() }) classes++
    if (password.any { it.isUpperCase() }) classes++
    if (password.any { it.isDigit() }) classes++
    if (password.any { !it.isLetterOrDigit() }) classes++
    val distinct = password.toSet().size
    return when {
        password.length >= 16 && classes >= 2 && distinct >= 8 -> PasswordStrength.Strong
        password.length >= 12 && classes >= 3 && distinct >= 6 -> PasswordStrength.Strong
        password.length >= 10 && classes >= 2 && distinct >= 5 -> PasswordStrength.Fair
        else -> PasswordStrength.Weak
    }
}

fun PasswordStrength.hint(): String = when (this) {
    PasswordStrength.TooShort -> "Use at least $MIN_VAULT_PASSWORD characters."
    PasswordStrength.Weak -> "Weak. A long passphrase of several words is best."
    PasswordStrength.Fair -> "Fair. Longer is better."
    PasswordStrength.Strong -> "Strong."
}

const val MIN_VAULT_PASSWORD = 8
