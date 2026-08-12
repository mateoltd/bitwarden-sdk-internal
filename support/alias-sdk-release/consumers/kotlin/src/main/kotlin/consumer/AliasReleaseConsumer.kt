package consumer

import com.bitwarden.sdk.createAliasReference
import com.bitwarden.sdk.parseAliasReference
import com.bitwarden.sdk.serializeAliasReference
import uniffi.bitwarden_alias.Alias
import uniffi.bitwarden_alias.AliasProvider
import uniffi.bitwarden_alias.AliasProviderIdentity
import uniffi.bitwarden_alias.MailboxRef

fun main() {
    val connectionId = "11111111-1111-4111-8111-111111111111"
    val identity = AliasProviderIdentity(
        provider = AliasProvider.SIMPLE_LOGIN,
        instance = "https://aliases.example.test/",
        connectionId = connectionId,
    )
    val mailbox = MailboxRef(1uL, "owner@example.test")
    val providerAlias = Alias(
        id = 7uL,
        email = "alias@example.test",
        creationDate = "2026-08-12T00:00:00Z",
        creationTimestamp = 1,
        enabled = true,
        note = null,
        name = null,
        nbForward = 0uL,
        nbBlock = 0uL,
        nbReply = 0uL,
        mailbox = mailbox,
        mailboxes = listOf(mailbox),
        supportPgp = false,
        disablePgp = false,
        latestActivity = null,
        pinned = false,
    )

    val encoded = createAliasReference(identity, providerAlias)
    val expected =
        "{\"version\":1,\"provider\":\"simplelogin\"," +
            "\"providerInstance\":\"https://aliases.example.test/\"," +
            "\"connectionId\":\"$connectionId\",\"aliasId\":7," +
            "\"address\":\"alias@example.test\"}"
    val parsed = parseAliasReference(encoded)
    check(encoded == expected)
    check(parsed.version == 1u)
    check(parsed.connectionId == connectionId)
    check(serializeAliasReference(parsed) == encoded)
    rejectedReferences(encoded).forEach { rejected ->
        check(runCatching { parseAliasReference(rejected) }.isFailure)
    }
    println("Kotlin alias SDK clean-room consumer passed")
}

private fun rejectedReferences(canonical: String) = listOf(
    canonical.replace("\"version\":1,", ""),
    canonical.replace("\"version\":1", "\"version\":0"),
    "{\"version\":",
    canonical.replace("\"version\":1", "\"version\":2"),
    canonical.replace("\"version\":1", "\"version\":4294967295"),
)
