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
        let expected =
            "{\"version\":1,\"provider\":\"simplelogin\"," +
            "\"providerInstance\":\"https://aliases.example.test/\"," +
            "\"connectionId\":\"\(connectionId)\",\"aliasId\":7," +
            "\"address\":\"alias@example.test\"}"
        let parsed = try parseAliasReference(value: encoded)
        let serialized = try serializeAliasReference(reference: parsed)
        guard encoded == expected,
              parsed.version == 1,
              parsed.connectionId == connectionId,
              serialized == encoded
        else {
            return false
        }
        for rejected in rejectedReferences(from: encoded) {
            do {
                _ = try parseAliasReference(value: rejected)
                return false
            } catch {}
        }
        return true
    }

    private static func rejectedReferences(from canonical: String) -> [String] {
        [
            canonical.replacingOccurrences(of: "\"version\":1,", with: ""),
            canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":0"),
            "{\"version\":",
            canonical.replacingOccurrences(of: "\"version\":1", with: "\"version\":2"),
            canonical.replacingOccurrences(
                of: "\"version\":1",
                with: "\"version\":4294967295"
            ),
        ]
    }
}
