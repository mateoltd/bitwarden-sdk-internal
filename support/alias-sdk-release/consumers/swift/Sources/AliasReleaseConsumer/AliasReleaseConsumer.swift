import BitwardenSdk

public enum AliasReleaseConsumer {
    public static func validateReferenceIdentity() throws -> Bool {
        let connectionId = "11111111-1111-4111-8111-111111111111"
        let capabilities = AliasProviderCapabilities(
            create: true,
            list: true,
            get: true,
            enableDisable: true,
            delete: true,
            createSendReplyIdentity: true,
            listSendReplyIdentities: true,
            removeSendReplyIdentity: true,
            extensions: ["send-reply.block"]
        )
        let connection = AliasConnection(
            version: 1,
            connectionId: connectionId,
            adapter: AliasAdapterDescriptor(
                adapterId: "example.adapter",
                capabilities: capabilities
            )
        )
        let identity = AliasIdentity(
            version: 1,
            connectionId: connection.connectionId,
            aliasId: "remote/object:7",
            address: "alias@example.test"
        )

        let encoded = try createAliasReference(identity: identity)
        let expected =
            "{\"version\":1,\"connectionId\":\"\(connectionId)\"," +
            "\"aliasId\":\"remote/object:7\"," +
            "\"address\":\"alias@example.test\"}"
        let parsed = try parseAliasReference(value: encoded)
        let serialized = try serializeAliasReference(reference: parsed)
        guard encoded == expected,
              parsed.version == 1,
              parsed.connectionId == connectionId,
              parsed.aliasId == "remote/object:7",
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
        let journal = AliasJournal(
            version: 1,
            connectionId: connectionId,
            events: [
                AliasJournalEvent(
                    version: 1,
                    eventId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    operationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    replicaId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    sequence: 1,
                    causal: [],
                    operation: .delete,
                    phase: .acknowledged,
                    target: identity,
                    lifecycle: .deleted,
                    error: nil
                ),
            ]
        )
        let canonicalJournal = try canonicalizeAliasJournal(journal: journal)
        let mergedJournal = try mergeAliasJournals(
            left: AliasJournal(version: 1, connectionId: connectionId, events: []),
            right: canonicalJournal
        )
        let journalState = try reduceAliasJournal(journal: mergedJournal)
        return journalState.resources.count == 1 &&
            journalState.resources[0].identity.aliasId == identity.aliasId &&
            journalState.resources[0].tombstoned
    }

    public static func validateInjectedLifecycle() async throws -> Bool {
        let adapter = FixtureAdapter()
        let client = try AliasClient(adapter: adapter)
        let created = try await client.create(request: CreateAliasRequest(hostname: "example.test"))
        let listed = try await client.list(request: ListAliasesRequest(pageToken: nil))
        let fetched = try await client.get(identity: created.identity)
        let disabled = try await client.setEnabled(identity: created.identity, enabled: false)
        guard client.connection() == adapter.connection,
              listed.aliases == [created],
              fetched == created,
              disabled.lifecycle == .disabled
        else {
            return false
        }
        let reply = try await client.createSendReplyIdentity(
            request: CreateSendReplyIdentityRequest(
                alias: created.identity,
                recipient: "recipient@example.test"
            )
        )
        let listedReplies = try await client.listSendReplyIdentities(
            alias: created.identity,
            pageToken: nil
        )
        guard listedReplies.identities == [reply] else {
            return false
        }
        let blocked = try await client.setSendReplyBlocked(identity: reply, blocked: true)
        guard blocked.identityId == reply.identityId,
              blocked.recipient == reply.recipient,
              blocked.address == reply.address,
              blocked.blocked == true
        else {
            return false
        }
        try await client.removeSendReplyIdentity(identity: blocked)
        let deleted = try await client.delete(identity: created.identity)
        return deleted.deleted
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

    private final class FixtureAdapter: AliasProviderAdapter, Sendable {
        let connection: AliasConnection

        init() {
            let capabilities = AliasProviderCapabilities(
                create: true,
                list: true,
                get: true,
                enableDisable: true,
                delete: true,
                createSendReplyIdentity: true,
                listSendReplyIdentities: true,
                removeSendReplyIdentity: true,
                extensions: ["send-reply.block"]
            )
            connection = AliasConnection(
                version: 1,
                connectionId: "11111111-1111-4111-8111-111111111111",
                adapter: AliasAdapterDescriptor(
                    adapterId: "example.adapter",
                    capabilities: capabilities
                )
            )
        }

        func descriptor() throws -> AliasAdapterDescriptor { connection.adapter }

        func connectionId() throws -> String { connection.connectionId }

        func create(request: CreateAliasRequest) async throws -> Alias { alias(enabled: true) }

        func list(request: ListAliasesRequest) async throws -> AliasPage {
            AliasPage(aliases: [alias(enabled: true)], nextPageToken: nil)
        }

        func get(identity: AliasIdentity) async throws -> Alias { alias(enabled: true) }

        func setEnabled(identity: AliasIdentity, enabled: Bool) async throws -> Alias {
            alias(enabled: enabled)
        }

        func delete(identity: AliasIdentity) async throws -> DeleteAliasResult {
            DeleteAliasResult(identity: identity, deleted: true)
        }

        func createSendReplyIdentity(
            request: CreateSendReplyIdentityRequest
        ) async throws -> SendReplyIdentity {
            sendReplyIdentity(alias: request.alias, recipient: request.recipient)
        }

        func listSendReplyIdentities(
            alias: AliasIdentity,
            pageToken: String?
        ) async throws -> SendReplyIdentityPage {
            SendReplyIdentityPage(
                identities: [sendReplyIdentity(
                    alias: alias,
                    recipient: "recipient@example.test"
                )],
                nextPageToken: nil
            )
        }

        func removeSendReplyIdentity(identity: SendReplyIdentity) async throws {}

        func setSendReplyBlocked(
            identity: SendReplyIdentity,
            blocked: Bool
        ) async throws -> SendReplyIdentity {
            SendReplyIdentity(
                alias: identity.alias,
                identityId: identity.identityId,
                recipient: identity.recipient,
                address: identity.address,
                valid: identity.valid,
                blocked: blocked
            )
        }

        private func alias(enabled: Bool) -> Alias {
            Alias(
                identity: AliasIdentity(
                    version: 1,
                    connectionId: connection.connectionId,
                    aliasId: "remote/object:7",
                    address: "alias@example.test"
                ),
                lifecycle: enabled ? .enabled : .disabled,
                freshness: .current,
                consistency: .clean,
                label: nil,
                capabilities: connection.adapter.capabilities
            )
        }

        private func sendReplyIdentity(
            alias: AliasIdentity,
            recipient: String
        ) -> SendReplyIdentity {
            SendReplyIdentity(
                alias: alias,
                identityId: "reply/object:9",
                recipient: recipient,
                address: "reply@example.test",
                valid: true,
                blocked: false
            )
        }
    }
}
