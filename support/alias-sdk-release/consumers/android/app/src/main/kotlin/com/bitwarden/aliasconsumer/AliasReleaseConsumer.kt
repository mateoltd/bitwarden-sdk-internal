package com.bitwarden.aliasconsumer

import com.bitwarden.alias.Alias
import com.bitwarden.alias.AliasAdapterDescriptor
import com.bitwarden.alias.AliasClient
import com.bitwarden.alias.AliasConnection
import com.bitwarden.alias.AliasConsistency
import com.bitwarden.alias.AliasFreshness
import com.bitwarden.alias.AliasIdentity
import com.bitwarden.alias.AliasJournal
import com.bitwarden.alias.AliasJournalEvent
import com.bitwarden.alias.AliasLifecycleState
import com.bitwarden.alias.AliasOperationKind
import com.bitwarden.alias.AliasOperationPhase
import com.bitwarden.alias.AliasPage
import com.bitwarden.alias.AliasProviderAdapter
import com.bitwarden.alias.AliasProviderCapabilities
import com.bitwarden.alias.CreateAliasRequest
import com.bitwarden.alias.CreateSendReplyIdentityRequest
import com.bitwarden.alias.DeleteAliasResult
import com.bitwarden.alias.ListAliasesRequest
import com.bitwarden.alias.SendReplyIdentity
import com.bitwarden.alias.SendReplyIdentityPage
import com.bitwarden.sdk.canonicalizeAliasJournal
import com.bitwarden.sdk.createAliasReference
import com.bitwarden.sdk.mergeAliasJournals
import com.bitwarden.sdk.parseAliasReference
import com.bitwarden.sdk.reduceAliasJournal
import com.bitwarden.sdk.serializeAliasReference
import kotlinx.coroutines.runBlocking

object AliasReleaseConsumer {
    fun compileProbe(): Boolean {
        val connectionId = "11111111-1111-4111-8111-111111111111"
        val capabilities = AliasProviderCapabilities(
            create = true,
            list = true,
            get = true,
            enableDisable = true,
            delete = true,
            createSendReplyIdentity = true,
            listSendReplyIdentities = true,
            removeSendReplyIdentity = true,
            extensions = listOf("send-reply.block"),
        )
        val connection = AliasConnection(
            version = 1u,
            connectionId = connectionId,
            adapter = AliasAdapterDescriptor("example.adapter", capabilities),
        )
        val identity = AliasIdentity(
            version = 1u,
            connectionId = connection.connectionId,
            aliasId = "remote/object:7",
            address = "alias@example.test",
        )

        val encoded = createAliasReference(identity)
        val expected =
            "{\"version\":1,\"connectionId\":\"$connectionId\"," +
                "\"aliasId\":\"remote/object:7\"," +
                "\"address\":\"alias@example.test\"}"
        val parsed = parseAliasReference(encoded)
        val injectedClient = AliasClient(FixtureAdapter(connection))
        val injectedConnectionMatches = injectedClient.connection() == connection
        val (created, blockedReply) = runBlocking {
            val created = injectedClient.create(CreateAliasRequest("example.test"))
            val reply = injectedClient.createSendReplyIdentity(
                CreateSendReplyIdentityRequest(created.identity, "recipient@example.test"),
            )
            created to injectedClient.setSendReplyBlocked(reply, true)
        }
        injectedClient.close()
        val journal = AliasJournal(
            version = 1u,
            connectionId = connectionId,
            events = listOf(
                AliasJournalEvent(
                    version = 1u,
                    eventId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                    operationId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
                    replicaId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
                    sequence = 1uL,
                    causal = emptyList(),
                    operation = AliasOperationKind.DELETE,
                    phase = AliasOperationPhase.ACKNOWLEDGED,
                    target = identity,
                    lifecycle = AliasLifecycleState.DELETED,
                    error = null,
                ),
            ),
        )
        val canonicalJournal = canonicalizeAliasJournal(journal)
        val mergedJournal = mergeAliasJournals(
            AliasJournal(1u, connectionId, emptyList()),
            canonicalJournal,
        )
        val state = reduceAliasJournal(mergedJournal)
        return state.resources.single().tombstoned &&
            state.resources.single().identity.aliasId == identity.aliasId &&
            injectedConnectionMatches &&
            created.identity == identity &&
            blockedReply.blocked == true &&
            encoded == expected &&
            parsed.version == 1u &&
            parsed.connectionId == connectionId &&
            parsed.aliasId == "remote/object:7" &&
            serializeAliasReference(parsed) == encoded &&
            rejectedReferences(encoded).all { rejected ->
                runCatching { parseAliasReference(rejected) }.isFailure
            }
    }

    private fun rejectedReferences(canonical: String) = listOf(
        canonical.replace("\"version\":1,", ""),
        canonical.replace("\"version\":1", "\"version\":0"),
        "{\"version\":",
        canonical.replace("\"version\":1", "\"version\":2"),
        canonical.replace("\"version\":1", "\"version\":4294967295"),
    )

    private class FixtureAdapter(
        private val connection: AliasConnection,
    ) : AliasProviderAdapter {
        override fun descriptor() = connection.adapter

        override fun connectionId() = connection.connectionId

        override suspend fun create(request: CreateAliasRequest) = alias(true)

        override suspend fun list(request: ListAliasesRequest) = AliasPage(listOf(alias(true)), null)

        override suspend fun get(identity: AliasIdentity) = alias(true)

        override suspend fun setEnabled(identity: AliasIdentity, enabled: Boolean) = alias(enabled)

        override suspend fun delete(identity: AliasIdentity) = DeleteAliasResult(identity, true)

        override suspend fun createSendReplyIdentity(
            request: CreateSendReplyIdentityRequest,
        ) = sendReplyIdentity(request.alias, request.recipient)

        override suspend fun listSendReplyIdentities(
            alias: AliasIdentity,
            pageToken: String?,
        ) = SendReplyIdentityPage(listOf(sendReplyIdentity(alias, "recipient@example.test")), null)

        override suspend fun removeSendReplyIdentity(identity: SendReplyIdentity) = Unit

        override suspend fun setSendReplyBlocked(
            identity: SendReplyIdentity,
            blocked: Boolean,
        ) = identity.copy(blocked = blocked)

        private fun alias(enabled: Boolean) = Alias(
            identity = AliasIdentity(
                1u,
                connection.connectionId,
                "remote/object:7",
                "alias@example.test",
            ),
            lifecycle = if (enabled) AliasLifecycleState.ENABLED else AliasLifecycleState.DISABLED,
            freshness = AliasFreshness.CURRENT,
            consistency = AliasConsistency.CLEAN,
            label = null,
            capabilities = connection.adapter.capabilities,
        )

        private fun sendReplyIdentity(alias: AliasIdentity, recipient: String) = SendReplyIdentity(
            alias = alias,
            identityId = "reply/object:9",
            recipient = recipient,
            address = "reply@example.test",
            valid = true,
            blocked = false,
        )
    }
}
