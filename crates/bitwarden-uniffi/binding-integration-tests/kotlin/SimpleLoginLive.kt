import kotlinx.coroutines.runBlocking
import uniffi.bitwarden_alias.AliasClientSettings
import uniffi.bitwarden_alias.AliasId
import uniffi.bitwarden_alias.ContactId
import uniffi.bitwarden_alias.CreateCustomAliasRequest
import uniffi.bitwarden_alias.CreateRandomAliasRequest
import uniffi.bitwarden_alias.SearchAliasesRequest
import uniffi.bitwarden_uniffi.AliasClient
import uniffi.bitwarden_uniffi.AliasUpdateRequest
import uniffi.bitwarden_uniffi.OptionalSensitiveStringUpdate
import java.util.UUID

fun main() = runBlocking {
    val baseUrl = requireNotNull(System.getenv("SIMPLELOGIN_API_URL"))
    val apiToken = requireNotNull(System.getenv("SIMPLELOGIN_API_TOKEN"))
    val unique = UUID.randomUUID().toString().lowercase()
    val hostname = "kotlin-$unique.integration.test"
    val searchText = "kotlin-live-$unique"
    val client = AliasClient(AliasClientSettings(baseUrl = baseUrl, apiToken = apiToken))
    val aliasIds = mutableListOf<AliasId>()
    var contactId: ContactId? = null

    try {
        val options = client.getAliasOptions(hostname)
        check(options.canCreate && options.suffixes.isNotEmpty())

        val mailboxes = client.listMailboxes()
        val mailbox = mailboxes.firstOrNull { it.verified && it.isDefault }
            ?: mailboxes.firstOrNull { it.verified }
            ?: error("the disposable account must have a verified mailbox")

        val alias = client.createRandomAlias(
            CreateRandomAliasRequest(hostname = hostname, mode = null, note = searchText),
        )
        aliasIds += alias.id
        check(alias.id > 0uL)

        check(client.listAliases(0u, null).aliases.any { it.id == alias.id })
        check(
            client.searchAliases(SearchAliasesRequest(searchText, 0u, null)).aliases
                .any { it.id == alias.id },
        )
        check(client.getAlias(alias.id).email == alias.email)

        val updated = client.updateAlias(
            alias.id,
            AliasUpdateRequest(
                note = OptionalSensitiveStringUpdate.Set("updated-$searchText"),
                name = OptionalSensitiveStringUpdate.Set("Kotlin live alias"),
                mailboxIds = null,
                disablePgp = null,
                pinned = true,
            ),
        )
        check(updated.id == alias.id && updated.name == "Kotlin live alias")
        val cleared = client.updateAlias(
            alias.id,
            AliasUpdateRequest(
                note = OptionalSensitiveStringUpdate.Clear,
                name = null,
                mailboxIds = null,
                disablePgp = null,
                pinned = null,
            ),
        )
        check(cleared.note == null)

        check(!client.disableAlias(alias.id).enabled)
        check(client.enableAlias(alias.id).enabled)
        check(client.setAliasEnabled(alias.id, true).enabled)
        check(client.getAliasRecommendation(hostname)?.alias == alias.email)

        val reverse = client.createReverseAlias(alias.id, "kotlin-contact-$unique@example.net")
        contactId = reverse.id
        check(reverse.id > 0uL)
        check(client.listContacts(alias.id, 0u).contacts.any { it.id == reverse.id })
        check(client.listReverseAliases(alias.id, 0u).aliasId == alias.id)
        check(client.toggleContactBlocked(reverse.id).blockForward)
        check(client.deleteContact(reverse.id).deleted)
        contactId = null

        check(client.listDomains().isNotEmpty())
        client.listCustomDomains()

        val suffix = options.suffixes.firstOrNull { !it.isPremium }
            ?: error("the disposable account must expose a non-premium suffix")
        val custom = client.createCustomAlias(
            CreateCustomAliasRequest(
                aliasPrefix = "kotlin${System.currentTimeMillis()}",
                signedSuffix = suffix.signedSuffix,
                mailboxIds = listOf(mailbox.id),
                hostname = null,
                note = "Kotlin custom alias",
                name = "Kotlin custom",
            ),
        )
        aliasIds += custom.id
        check(custom.id != alias.id)
    } finally {
        contactId?.let {
            try {
                client.deleteContact(it)
            } catch (_: Exception) {
                // Best-effort cleanup after a preceding assertion or transport failure.
            }
        }
        aliasIds.asReversed().forEach {
            try {
                client.deleteAlias(it)
            } catch (_: Exception) {
                // Best-effort cleanup after a preceding assertion or transport failure.
            }
        }
        client.close()
    }

    println("Kotlin SimpleLogin alias lifecycle passed")
}
