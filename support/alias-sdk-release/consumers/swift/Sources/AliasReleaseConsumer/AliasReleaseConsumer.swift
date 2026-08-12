import BitwardenSdk

public enum AliasReleaseConsumer {
    public static func validateReferenceIdentity() throws -> Bool {
        let connectionId = "11111111-1111-4111-8111-111111111111"
        let identity = AliasProviderIdentity(
            provider: .simpleLogin,
            instance: "https://aliases.example.test/",
            connectionId: connectionId
        )
        let mailbox = MailboxRef(id: 1, email: "owner@example.test")
        let providerAlias = Alias(
            id: 7,
            email: "alias@example.test",
            creationDate: "2026-08-12T00:00:00Z",
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

        let encoded = try createAliasReference(identity: identity, alias: providerAlias)
        let parsed = try parseAliasReference(value: encoded)
        return parsed.connectionId == connectionId
            && (try serializeAliasReference(reference: parsed)) == encoded
    }
}
