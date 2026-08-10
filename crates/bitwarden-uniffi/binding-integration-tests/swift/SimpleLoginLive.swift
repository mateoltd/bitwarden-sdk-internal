import Foundation

@main
struct SimpleLoginLive {
    static func main() async throws {
        let environment = ProcessInfo.processInfo.environment
        guard
            let baseUrl = environment["SIMPLELOGIN_API_URL"],
            let apiToken = environment["SIMPLELOGIN_API_TOKEN"]
        else {
            fatalError("SIMPLELOGIN_API_URL and SIMPLELOGIN_API_TOKEN are required")
        }

        let unique = UUID().uuidString.lowercased()
        let hostname = "swift-\(unique).integration.test"
        let searchText = "swift-live-\(unique)"
        let client = try AliasClient(
            settings: AliasClientSettings(baseUrl: baseUrl, apiToken: apiToken)
        )
        var aliasIds: [AliasId] = []
        var contactId: ContactId?

        do {
            let options = try await client.getAliasOptions(hostname: hostname)
            precondition(options.canCreate && !options.suffixes.isEmpty)

            let mailboxes = try await client.listMailboxes()
            guard let mailbox = mailboxes.first(where: { $0.verified && $0.isDefault })
                ?? mailboxes.first(where: { $0.verified })
            else {
                fatalError("the disposable account must have a verified mailbox")
            }

            let alias = try await client.createRandomAlias(
                request: CreateRandomAliasRequest(
                    hostname: hostname,
                    mode: nil,
                    note: searchText
                )
            )
            aliasIds.append(alias.id)
            precondition(alias.id > 0)

            let listed = try await client.listAliases(page: 0, filter: nil)
            precondition(listed.aliases.contains(where: { $0.id == alias.id }))
            let searched = try await client.searchAliases(
                request: SearchAliasesRequest(query: searchText, page: 0, filter: nil)
            )
            precondition(searched.aliases.contains(where: { $0.id == alias.id }))
            let detail = try await client.getAlias(aliasId: alias.id)
            precondition(detail.email == alias.email)

            let updated = try await client.updateAlias(
                aliasId: alias.id,
                request: AliasUpdateRequest(
                    note: .set(value: "updated-\(searchText)"),
                    name: .set(value: "Swift live alias"),
                    mailboxIds: nil,
                    disablePgp: nil,
                    pinned: true
                )
            )
            precondition(updated.id == alias.id && updated.name == "Swift live alias")
            let cleared = try await client.updateAlias(
                aliasId: alias.id,
                request: AliasUpdateRequest(
                    note: .clear,
                    name: nil,
                    mailboxIds: nil,
                    disablePgp: nil,
                    pinned: nil
                )
            )
            precondition(cleared.note == nil)

            let disabled = try await client.disableAlias(aliasId: alias.id)
            precondition(!disabled.enabled)
            let enabled = try await client.enableAlias(aliasId: alias.id)
            precondition(enabled.enabled)
            let unchanged = try await client.setAliasEnabled(aliasId: alias.id, enabled: true)
            precondition(unchanged.enabled)
            let recommendation = try await client.getAliasRecommendation(hostname: hostname)
            precondition(recommendation?.alias == alias.email)

            let reverse = try await client.createContact(
                aliasId: alias.id,
                contact: "swift-contact-\(unique)@example.net"
            )
            contactId = reverse.id
            precondition(reverse.id > 0)
            let contacts = try await client.listContacts(aliasId: alias.id, page: 0)
            precondition(contacts.contacts.contains(where: { $0.id == reverse.id }))
            let reverseAliases = try await client.listReverseAliases(aliasId: alias.id, page: 0)
            precondition(reverseAliases.aliasId == alias.id)
            let blocked = try await client.toggleContactBlocked(contactId: reverse.id)
            precondition(blocked.blockForward)
            let contactDeleted = try await client.deleteContact(contactId: reverse.id)
            precondition(contactDeleted.deleted)
            contactId = nil

            let domains = try await client.listDomains()
            precondition(!domains.isEmpty)
            _ = try await client.listCustomDomains()

            guard let suffix = options.suffixes.first(where: { !$0.isPremium }) else {
                fatalError("the disposable account must expose a non-premium suffix")
            }
            let custom = try await client.createCustomAlias(
                request: CreateCustomAliasRequest(
                    aliasPrefix: "swift\(Int(Date().timeIntervalSince1970 * 1_000))",
                    signedSuffix: suffix.signedSuffix,
                    mailboxIds: [mailbox.id],
                    hostname: nil,
                    note: "Swift custom alias",
                    name: "Swift custom"
                )
            )
            aliasIds.append(custom.id)
            precondition(custom.id != alias.id)
        } catch {
            await cleanup(client: client, aliasIds: aliasIds, contactId: contactId)
            throw error
        }

        await cleanup(client: client, aliasIds: aliasIds, contactId: contactId)
        print("Swift SimpleLogin alias lifecycle passed")
    }

    private static func cleanup(
        client: AliasClient,
        aliasIds: [AliasId],
        contactId: ContactId?
    ) async {
        if let contactId {
            _ = try? await client.deleteContact(contactId: contactId)
        }
        for aliasId in aliasIds.reversed() {
            _ = try? await client.deleteAlias(aliasId: aliasId)
        }
    }
}
