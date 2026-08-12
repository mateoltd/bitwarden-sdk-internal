import com.bitwarden.sdk.applyAliasReconciliation
import com.bitwarden.sdk.bindAliasReference
import com.bitwarden.sdk.createAliasReference
import com.bitwarden.sdk.parseAliasReference
import com.bitwarden.sdk.planAliasReconciliation
import com.bitwarden.sdk.serializeAliasReference
import com.bitwarden.vault.CipherId
import com.bitwarden.vault.CipherRepromptType
import com.bitwarden.vault.CipherType
import com.bitwarden.vault.CipherView
import com.bitwarden.vault.FieldType
import com.bitwarden.vault.FieldView
import com.bitwarden.vault.LoginView
import java.time.Instant
import uniffi.bitwarden_alias.Alias
import uniffi.bitwarden_alias.AliasProvider
import uniffi.bitwarden_alias.AliasProviderIdentity
import uniffi.bitwarden_alias.MailboxRef

private const val CONNECTION_ONE = "11111111-1111-4111-8111-111111111111"
private const val INSTANCE = "https://aliases.example.test/"
private const val REFERENCE_FIELD = "bitwarden.alias.reference"

fun main() {
    val firstIdentity = identity(CONNECTION_ONE)
    val providerAlias = alias(7uL, "first@example.test")
    val encoded = createAliasReference(firstIdentity, providerAlias)
    val expected =
        "{\"version\":1,\"provider\":\"simplelogin\",\"providerInstance\":\"$INSTANCE\"," +
            "\"connectionId\":\"$CONNECTION_ONE\",\"aliasId\":7,\"address\":\"first@example.test\"}"
    check(encoded == expected)

    val parsed = parseAliasReference(encoded)
    check(parsed.version == 1u && parsed.connectionId == CONNECTION_ONE && parsed.aliasId == 7uL)
    check(serializeAliasReference(parsed) == encoded)
    rejectedReferences(expected).forEach { rejected ->
        check(runCatching { parseAliasReference(rejected) }.isFailure)
    }

    val bound = bindAliasReference(encoded, cipher(1, "first@example.test"))
    check(bound.changed)
    check(
        bound.cipher.fields ==
            listOf(FieldView(REFERENCE_FIELD, encoded, FieldType.HIDDEN, null)),
    )

    val plan = planAliasReconciliation(
        firstIdentity,
        listOf(providerAlias),
        listOf(bound.cipher),
    )
    check(plan.summary.matched == 1uL && plan.actions.isEmpty())
    val applied = applyAliasReconciliation(
        plan,
        listOf(providerAlias),
        listOf(bound.cipher),
    )
    check(applied.result.changedCipherIds.isEmpty())
    val repeated = planAliasReconciliation(firstIdentity, listOf(providerAlias), applied.ciphers)
    check(repeated.summary.matched == 1uL && repeated.actions.isEmpty())

    println("Kotlin alias reference consumer passed")
}

private fun rejectedReferences(canonical: String) = listOf(
    canonical.replace("\"version\":1,", ""),
    canonical.replace("\"version\":1", "\"version\":0"),
    "{\"version\":",
    canonical.replace("\"version\":1", "\"version\":2"),
    canonical.replace("\"version\":1", "\"version\":4294967295"),
)

private fun identity(connectionId: String) = AliasProviderIdentity(
    provider = AliasProvider.SIMPLE_LOGIN,
    instance = INSTANCE,
    connectionId = connectionId,
)

private fun alias(id: ULong, address: String): Alias {
    val mailbox = MailboxRef(1uL, "owner@example.test")
    return Alias(
        id = id,
        email = address,
        creationDate = "2026-08-11T10:00:00Z",
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
}

private fun cipherId(index: Int): CipherId = "00000000-0000-4000-8000-%012x".format(index)

private fun cipher(
    id: Int,
    username: String,
    fields: List<FieldView> = emptyList(),
) = CipherView(
    id = cipherId(id),
    organizationId = null,
    folderId = null,
    collectionIds = emptyList(),
    key = null,
    name = "Alias $id",
    notes = null,
    type = CipherType.LOGIN,
    login = LoginView(username, null, null, null, null, null, null),
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
    fields = fields,
    passwordHistory = null,
    creationDate = Instant.EPOCH,
    deletedDate = null,
    revisionDate = Instant.EPOCH,
    archivedDate = null,
)
