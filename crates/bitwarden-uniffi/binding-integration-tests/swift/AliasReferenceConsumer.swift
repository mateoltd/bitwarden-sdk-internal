import Foundation

@main
struct AliasReferenceConsumer {
    private static let connectionOne = "11111111-1111-4111-8111-111111111111"
    private static let connectionTwo = "22222222-2222-4222-8222-222222222222"
    private static let instance = "https://aliases.example.test/"
    private static let referenceField = "bitwarden.alias.reference"

    static func main() throws {
        let firstIdentity = identity(connectionOne)
        let providerAlias = alias(id: 7, address: "first@example.test")
        let encoded = try createAliasReference(identity: firstIdentity, alias: providerAlias)
        let expected =
            "{\"version\":2,\"provider\":\"simplelogin\",\"providerInstance\":\"\(instance)\"," +
            "\"connectionId\":\"\(connectionOne)\",\"aliasId\":7,\"address\":\"first@example.test\"}"
        precondition(encoded == expected)

        let parsed = try parseAliasReference(value: encoded)
        precondition(parsed.version == 2 && parsed.connectionId == connectionOne && parsed.aliasId == 7)
        let reserialized = try serializeAliasReference(reference: parsed)
        precondition(reserialized == encoded)

        let bound = try bindAliasReference(
            value: encoded,
            cipher: cipher(id: 1, username: "first@example.test")
        )
        precondition(bound.changed)
        precondition(bound.cipher.fields == [
            FieldView(name: referenceField, value: encoded, type: .hidden, linkedId: nil)
        ])

        let plan = try planAliasReconciliation(
            provider: firstIdentity,
            aliases: [providerAlias],
            ciphers: [cipher(id: 2, username: "first@example.test")]
        )
        precondition(plan.summary.matchedByAddress == 1 && plan.actions.count == 1)
        let applied = try applyAliasReconciliation(
            plan: plan,
            aliases: [providerAlias],
            ciphers: [cipher(id: 2, username: "first@example.test")]
        )
        precondition(applied.result.changedCipherIds == [cipherId(2)])
        let repeated = try planAliasReconciliation(
            provider: firstIdentity,
            aliases: [providerAlias],
            ciphers: applied.ciphers
        )
        precondition(repeated.summary.matched == 1 && repeated.actions.isEmpty)

        let legacy =
            "{\"version\":1,\"provider\":\"simplelogin\",\"providerInstance\":\"\(instance)\"," +
            "\"aliasId\":41,\"address\":\"legacy@example.test\"}"
        do {
            _ = try migrateAliasReference(
                value: legacy,
                connections: [firstIdentity, identity(connectionTwo)]
            )
            fatalError("ambiguous legacy reference unexpectedly migrated")
        } catch AliasReferenceError.AmbiguousLegacyReference {
            // The client must select one connection explicitly.
        }

        let migrated = try migrateAliasReference(value: legacy, connections: [firstIdentity])
        let migratedReference = try parseAliasReference(value: migrated)
        precondition(migratedReference.connectionId == connectionOne)
        let migratedCipher = try migrateCipherAliasReference(
            cipher: cipher(
                id: 3,
                username: "legacy@example.test",
                fields: [FieldView(name: referenceField, value: legacy, type: .hidden, linkedId: nil)]
            ),
            connections: [firstIdentity]
        )
        precondition(migratedCipher.migration.changed)
        precondition(migratedCipher.cipher.fields?.first?.value == migrated)

        print("Swift alias reference consumer passed")
    }

    private static func identity(_ connectionId: String) -> AliasProviderIdentity {
        AliasProviderIdentity(
            provider: .simpleLogin,
            instance: instance,
            connectionId: connectionId
        )
    }

    private static func alias(id: UInt64, address: String) -> Alias {
        let mailbox = MailboxRef(id: 1, email: "owner@example.test")
        return Alias(
            id: id,
            email: address,
            creationDate: "2026-08-11T10:00:00Z",
            creationTimestamp: 1,
            enabled: true,
            note: nil,
            name: nil,
            nbForward: 0,
            nbBlock: 0,
            nbReply: 0,
            mailbox: mailbox,
            mailboxes: [mailbox],
            supportPgp: false,
            disablePgp: false,
            latestActivity: nil,
            pinned: false
        )
    }

    private static func cipherId(_ index: Int) -> CipherId {
        String(format: "00000000-0000-4000-8000-%012x", index)
    }

    private static func cipher(
        id: Int,
        username: String,
        fields: [FieldView] = []
    ) -> CipherView {
        CipherView(
            id: cipherId(id),
            organizationId: nil,
            folderId: nil,
            collectionIds: [],
            key: nil,
            name: "Alias \(id)",
            notes: nil,
            type: .login,
            login: LoginView(
                username: username,
                password: nil,
                passwordRevisionDate: nil,
                uris: nil,
                totp: nil,
                autofillOnPageLoad: nil,
                fido2Credentials: nil
            ),
            identity: nil,
            card: nil,
            secureNote: nil,
            sshKey: nil,
            bankAccount: nil,
            driversLicense: nil,
            passport: nil,
            favorite: false,
            reprompt: .none,
            organizationUseTotp: false,
            edit: true,
            permissions: nil,
            viewPassword: true,
            localData: nil,
            attachments: nil,
            attachmentDecryptionFailures: nil,
            fields: fields,
            passwordHistory: nil,
            creationDate: Date(timeIntervalSince1970: 0),
            deletedDate: nil,
            revisionDate: Date(timeIntervalSince1970: 0),
            archivedDate: nil
        )
    }
}
