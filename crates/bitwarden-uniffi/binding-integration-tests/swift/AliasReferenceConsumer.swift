import BitwardenSdk
import Foundation

@main
struct AliasReferenceConsumer {
    private static let connectionOne = "11111111-1111-4111-8111-111111111111"
    private static let connectionTwo = "22222222-2222-4222-8222-222222222222"

    static func main() throws {
        let first = identity(connectionOne, "remote/object:7", "first@example.test")
        let encoded = try createAliasReference(identity: first)
        let expected =
            "{\"version\":1,\"connectionId\":\"\(connectionOne)\"," +
            "\"aliasId\":\"remote/object:7\",\"address\":\"first@example.test\"}"
        precondition(encoded == expected)

        let parsed = try parseAliasReference(value: encoded)
        precondition(parsed.version == 1)
        precondition(parsed.connectionId == connectionOne)
        precondition(parsed.aliasId == "remote/object:7")
        precondition(try serializeAliasReference(reference: parsed) == encoded)
        for rejected in rejectedReferences(from: expected) {
            do {
                _ = try parseAliasReference(value: rejected)
                preconditionFailure("invalid alias reference unexpectedly parsed")
            } catch {}
        }

        let bound = try bindAliasReference(
            value: encoded,
            cipher: cipher(id: 1, username: "first@example.test")
        )
        precondition(bound.changed)
        precondition(bound.cipher.login?.aliasReference == encoded)
        precondition(bound.cipher.fields.isEmpty)

        let firstAlias = alias(first)
        let secondAlias = alias(identity(connectionTwo, "remote/object:7", "second@example.test"))
        let secondCipher = try bindAliasReference(
            value: createAliasReference(identity: secondAlias.identity),
            cipher: cipher(id: 2, username: "second@example.test")
        ).cipher
        let plan = try planAliasReconciliation(
            connectionId: connectionOne,
            aliases: [firstAlias],
            ciphers: [bound.cipher, secondCipher]
        )
        precondition(plan.summary.matched == 1)
        precondition(plan.summary.skippedCiphers == 1)
        let applied = try applyAliasReconciliation(
            plan: plan,
            aliases: [firstAlias],
            ciphers: [bound.cipher, secondCipher]
        )
        precondition(applied.result.changedCipherIds.isEmpty)

        var edited = bound.cipher
        edited.login?.username = "edited@example.test"
        let cleared = try clearAliasReferenceIfUsernameChanged(cipher: edited)
        precondition(cleared.changed)
        precondition(cleared.cipher.login?.aliasReference == nil)
        precondition(cleared.cipher.login?.username == "edited@example.test")

        print("Swift provider-neutral alias consumer passed")
    }

    private static func rejectedReferences(from canonical: String) -> [String] {
        [
            canonical.replacingOccurrences(of: "\"version\":1,", with: ""),
            canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":0"),
            "{\"version\":",
            canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":2"),
            canonical.replacingOccurrences(
                of: "\"aliasId\":\"remote/object:7\"",
                with: "\"aliasId\":7"
            ),
        ]
    }

    private static func capabilities() -> AliasProviderCapabilities {
        AliasProviderCapabilities(
            create: true,
            list: true,
            get: true,
            enableDisable: true,
            delete: true,
            createSendReplyIdentity: true,
            listSendReplyIdentities: true,
            removeSendReplyIdentity: true,
            extensions: []
        )
    }

    private static func identity(
        _ connectionId: String,
        _ aliasId: String,
        _ address: String
    ) -> AliasIdentity {
        AliasIdentity(version: 1, connectionId: connectionId, aliasId: aliasId, address: address)
    }

    private static func alias(_ identity: AliasIdentity) -> Alias {
        Alias(
            identity: identity,
            lifecycle: .enabled,
            freshness: .current,
            consistency: .clean,
            label: nil,
            capabilities: capabilities()
        )
    }

    private static func cipherId(_ index: Int) -> CipherId {
        String(format: "00000000-0000-4000-8000-%012x", index)
    }

    private static func cipher(id: Int, username: String) -> CipherView {
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
                aliasReference: nil,
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
            fields: [],
            passwordHistory: nil,
            creationDate: Date(timeIntervalSince1970: 0),
            deletedDate: nil,
            revisionDate: Date(timeIntervalSince1970: 0),
            archivedDate: nil
        )
    }
}
