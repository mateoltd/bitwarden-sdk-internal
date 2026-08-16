import {
  Alias,
  AliasClient,
  AliasConnection,
  AliasIdentity,
  AliasJournal,
  AliasProviderAdapter,
  SensitiveString,
  create_alias_reference,
  canonicalize_alias_journal,
  merge_alias_journals,
  parse_alias_reference,
  reduce_alias_journal,
  serialize_alias_reference,
} from "@bitwarden/sdk-internal";

const connectionId = "11111111-1111-4111-8111-111111111111";
const capabilities = {
  create: true,
  list: true,
  get: true,
  enableDisable: true,
  delete: true,
  createSendReplyIdentity: true,
  listSendReplyIdentities: true,
  removeSendReplyIdentity: true,
  extensions: ["send-reply.block"],
};
const connection: AliasConnection = {
  version: 1,
  connectionId,
  adapter: { adapterId: "example.adapter", capabilities },
};
const sensitive = (value: string): SensitiveString => value as SensitiveString;
const identity: AliasIdentity = {
  version: 1,
  connectionId: connection.connectionId,
  aliasId: "remote/object:7",
  address: sensitive("alias@example.test"),
};

const alias = (enabled: boolean): Alias => ({
  identity,
  lifecycle: enabled ? "enabled" : "disabled",
  freshness: "current",
  consistency: "clean",
  label: undefined,
  capabilities,
});

const adapter: AliasProviderAdapter = {
  create: async () => ({ status: "success", value: alias(true) }),
  list: async () => ({
    status: "success",
    value: { aliases: [alias(true)], nextPageToken: undefined },
  }),
  get: async () => ({ status: "success", value: alias(true) }),
  setEnabled: async (_identity, enabled) => ({
    status: "success",
    value: alias(enabled),
  }),
  delete: async (deletedIdentity) => ({
    status: "success",
    value: { identity: deletedIdentity, deleted: true },
  }),
  createSendReplyIdentity: async ({ alias: replyAlias, recipient }) => ({
    status: "success",
    value: {
      alias: replyAlias,
      identityId: "reply/object:9",
      recipient,
      address: sensitive("reply@example.test"),
      valid: true,
      blocked: false,
    },
  }),
  listSendReplyIdentities: async () => ({
    status: "success",
    value: { identities: [], nextPageToken: undefined },
  }),
  removeSendReplyIdentity: async () => ({ status: "success", value: null }),
  setSendReplyBlocked: async (reply, blocked) => ({
    status: "success",
    value: { ...reply, blocked },
  }),
};

export async function validateInjectedLifecycle(): Promise<boolean> {
  const client = new AliasClient(connection, adapter);
  const created = await client.create({ hostname: sensitive("example.test") });
  const reply = await client.create_send_reply_identity({
    alias: created.identity,
    recipient: sensitive("recipient@example.test"),
  });
  const blocked = await client.set_send_reply_blocked(reply, true);
  await client.remove_send_reply_identity(blocked);
  client.free();
  return blocked.blocked === true && blocked.identityId === reply.identityId;
}

const encoded = create_alias_reference(identity);
const parsed = parse_alias_reference(encoded);
const expected =
  `{"version":1,"connectionId":"${connectionId}",` +
  `"aliasId":"remote/object:7","address":"alias@example.test"}`;

if (
  encoded !== expected ||
  parsed.version !== 1 ||
  parsed.connectionId !== connectionId ||
  parsed.aliasId !== "remote/object:7" ||
  serialize_alias_reference(parsed) !== encoded
) {
  throw new Error("alias reference identity was not preserved");
}

const rejectedReferences = [
  encoded.replace('"version":1,', ""),
  encoded.replace('"version":1', '"version":0'),
  '{"version":',
  encoded.replace('"version":1', '"version":2'),
  encoded.replace('"version":1', '"version":4294967295'),
];
for (const rejected of rejectedReferences) {
  try {
    parse_alias_reference(rejected);
    throw new Error("non-v1 alias reference unexpectedly parsed");
  } catch (error) {
    if (error instanceof Error && error.message === "non-v1 alias reference unexpectedly parsed") {
      throw error;
    }
  }
}

const journal: AliasJournal = {
  version: 1,
  connectionId,
  events: [
    {
      version: 1,
      eventId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      operationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
      replicaId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
      sequence: BigInt(1),
      causal: [],
      operation: "delete",
      phase: "acknowledged",
      target: identity,
      lifecycle: "deleted",
      error: undefined,
    },
  ],
};
const canonicalJournal = canonicalize_alias_journal(journal);
const mergedJournal = merge_alias_journals(
  { version: 1, connectionId, events: [] },
  canonicalJournal,
);
const journalState = reduce_alias_journal(mergedJournal);
if (
  journalState.resources.length !== 1 ||
  journalState.resources[0].identity.aliasId !== identity.aliasId ||
  !journalState.resources[0].tombstoned
) {
  throw new Error("alias journal tombstone was not preserved");
}
