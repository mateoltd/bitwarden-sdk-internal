import com.bitwarden.sdk.applyAliasReconciliation
import com.bitwarden.sdk.bindAliasReference
import com.bitwarden.sdk.createAliasReference
import com.bitwarden.sdk.migrateAliasReference
import com.bitwarden.sdk.migrateCipherAliasReference
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
import uniffi.bitwarden_alias.AliasReferenceException
import uniffi.bitwarden_alias.MailboxRef

private const val CONNECTION_ONE = "11111111-1111-4111-8111-111111111111"
private const val CONNECTION_TWO = "22222222-2222-4222-8222-222222222222"
private const val INSTANCE = "https://aliases.example.test/"
private const val REFERENCE_FIELD = "bitwarden.alias.reference"

fun main() {
    val firstIdentity = identity(CONNECTION_ONE)
    val providerAlias = alias(7uL, "first@example.test")
    val encoded = createAliasReference(firstIdentity, providerAlias)
    val expected =
        "{\"version\":2,\"provider\":\"simplelogin\",\"providerInstance\":\"$INSTANCE\"," +
            "\"connectionId\":\"$CONNECTION_ONE\",\"aliasId\":7,\"address\":\"first@example.test\"}"
    check(encoded == expected)

    val parsed = parseAliasReference(encoded)
    check(parsed.version == 2u && parsed.connectionId == CONNECTION_ONE && parsed.aliasId == 7uL)
    check(serializeAliasReference(parsed) == encoded)

    val bound = bindAliasReference(encoded, cipher(1, "first@example.test"))
    check(bound.changed)
    check(
        bound.cipher.fields ==
            listOf(FieldView(REFERENCE_FIELD, encoded, FieldType.HIDDEN, null)),
    )

    val plan = planAliasReconciliation(
        firstIdentity,
        listOf(providerAlias),
        listOf(cipher(2, "first@example.test")),
    )
    check(plan.summary.matchedByAddress == 1uL && plan.actions.size == 1)
    val applied = applyAliasReconciliation(
        plan,
        listOf(providerAlias),
        listOf(cipher(2, "first@example.test")),
    )
    check(applied.result.changedCipherIds == listOf(cipherId(2)))
    val repeated = planAliasReconciliation(firstIdentity, listOf(providerAlias), applied.ciphers)
    check(repeated.summary.matched == 1uL && repeated.actions.isEmpty())

    val legacy =
        "{\"version\":1,\"provider\":\"simplelogin\",\"providerInstance\":\"$INSTANCE\"," +
            "\"aliasId\":41,\"address\":\"legacy@example.test\"}"
    try {
        migrateAliasReference(legacy, listOf(firstIdentity, identity(CONNECTION_TWO)))
        error("ambiguous legacy reference unexpectedly migrated")
    } catch (_: AliasReferenceException.AmbiguousLegacyReference) {
        // The client must select one connection explicitly.
    }

    val migrated = migrateAliasReference(legacy, listOf(firstIdentity))
    check(parseAliasReference(migrated).connectionId == CONNECTION_ONE)
    val migratedCipher = migrateCipherAliasReference(
        cipher(
            3,
            "legacy@example.test",
            listOf(FieldView(REFERENCE_FIELD, legacy, FieldType.HIDDEN, null)),
        ),
        listOf(firstIdentity),
    )
    check(migratedCipher.migration.changed)
    check(migratedCipher.cipher.fields?.first()?.value == migrated)

    println("Kotlin alias reference consumer passed")
}

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
