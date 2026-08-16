import com.bitwarden.sdk.applyAliasReconciliation
import com.bitwarden.sdk.bindAliasReference
import com.bitwarden.sdk.clearAliasReferenceIfUsernameChanged
import com.bitwarden.sdk.createAliasReference
import com.bitwarden.sdk.parseAliasReference
import com.bitwarden.sdk.planAliasReconciliation
import com.bitwarden.sdk.serializeAliasReference
import com.bitwarden.vault.CipherId
import com.bitwarden.vault.CipherRepromptType
import com.bitwarden.vault.CipherType
import com.bitwarden.vault.CipherView
import com.bitwarden.vault.LoginView
import java.time.Instant
import com.bitwarden.alias.Alias
import com.bitwarden.alias.AliasConsistency
import com.bitwarden.alias.AliasFreshness
import com.bitwarden.alias.AliasIdentity
import com.bitwarden.alias.AliasLifecycleState
import com.bitwarden.alias.AliasProviderCapabilities

private const val CONNECTION_ONE = "11111111-1111-4111-8111-111111111111"
private const val CONNECTION_TWO = "22222222-2222-4222-8222-222222222222"

fun main() {
    val first = identity(CONNECTION_ONE, "remote/object:7", "first@example.test")
    val encoded = createAliasReference(first)
    val expected =
        "{\"version\":1,\"connectionId\":\"$CONNECTION_ONE\"," +
            "\"aliasId\":\"remote/object:7\",\"address\":\"first@example.test\"}"
    check(encoded == expected)

    val parsed = parseAliasReference(encoded)
    check(parsed.version == 1u)
    check(parsed.connectionId == CONNECTION_ONE)
    check(parsed.aliasId == "remote/object:7")
    check(serializeAliasReference(parsed) == encoded)
    rejectedReferences(expected).forEach { rejected ->
        check(runCatching { parseAliasReference(rejected) }.isFailure)
    }

    val bound = bindAliasReference(encoded, cipher(1, "first@example.test"))
    check(bound.changed)
    check(bound.cipher.login?.aliasReference == encoded)
    check(bound.cipher.fields.isEmpty())

    val firstAlias = alias(first)
    val secondAlias = alias(identity(CONNECTION_TWO, "remote/object:7", "second@example.test"))
    val secondCipher = bindAliasReference(
        createAliasReference(secondAlias.identity),
        cipher(2, "second@example.test"),
    ).cipher
    val plan = planAliasReconciliation(
        CONNECTION_ONE,
        listOf(firstAlias),
        listOf(bound.cipher, secondCipher),
    )
    check(plan.summary.matched == 1uL)
    check(plan.summary.skippedCiphers == 1uL)
    val applied = applyAliasReconciliation(plan, listOf(firstAlias), listOf(bound.cipher, secondCipher))
    check(applied.result.changedCipherIds.isEmpty())

    val edited = bound.cipher.copy(
        login = bound.cipher.login?.copy(username = "edited@example.test"),
    )
    val cleared = clearAliasReferenceIfUsernameChanged(edited)
    check(cleared.changed)
    check(cleared.cipher.login?.aliasReference == null)
    check(cleared.cipher.login?.username == "edited@example.test")

    println("Kotlin provider-neutral alias consumer passed")
}

private fun rejectedReferences(canonical: String) = listOf(
    canonical.replace("\"version\":1,", ""),
    canonical.replace("\"version\":1", "\"version\":0"),
    "{\"version\":",
    canonical.replace("\"version\":1", "\"version\":2"),
    canonical.replace("\"aliasId\":\"remote/object:7\"", "\"aliasId\":7"),
)

private fun capabilities() = AliasProviderCapabilities(
    create = true,
    list = true,
    get = true,
    enableDisable = true,
    delete = true,
    createSendReplyIdentity = true,
    listSendReplyIdentities = true,
    removeSendReplyIdentity = true,
    extensions = emptyList(),
)

private fun identity(connectionId: String, aliasId: String, address: String) = AliasIdentity(
    version = 1u,
    connectionId = connectionId,
    aliasId = aliasId,
    address = address,
)

private fun alias(identity: AliasIdentity) = Alias(
    identity = identity,
    lifecycle = AliasLifecycleState.ENABLED,
    freshness = AliasFreshness.CURRENT,
    consistency = AliasConsistency.CLEAN,
    label = null,
    capabilities = capabilities(),
)

private fun cipherId(index: Int): CipherId = "00000000-0000-4000-8000-%012x".format(index)

private fun cipher(id: Int, username: String) = CipherView(
    id = cipherId(id),
    organizationId = null,
    folderId = null,
    collectionIds = emptyList(),
    key = null,
    name = "Alias $id",
    notes = null,
    type = CipherType.LOGIN,
    login = LoginView(username, null, null, null, null, null, null, null),
    identity = null,
    card = null,
    secureNote = null,
    sshKey = null,
    bankAccount = null,
    driversLicense = null,
    passport = null,
    favorite = false,
    reprompt = CipherRepromptType.NONE,
    organizationUseTotp = false,
    edit = true,
    permissions = null,
    viewPassword = true,
    localData = null,
    attachments = null,
    attachmentDecryptionFailures = null,
    fields = emptyList(),
    passwordHistory = null,
    creationDate = Instant.EPOCH,
    deletedDate = null,
    revisionDate = Instant.EPOCH,
    archivedDate = null,
)
