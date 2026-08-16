import {
  Alias,
  AliasClient,
  AliasConnection,
  AliasIdentity,
  AliasProviderAdapter,
  AliasProviderCapabilities,
  SensitiveString,
} from "@bitwarden/sdk-internal";

const CONNECTION_ID = "11111111-1111-4111-8111-111111111111";
const FOREIGN_CONNECTION_ID = "22222222-2222-4222-8222-222222222222";
const sensitive = (value: string): SensitiveString => value as SensitiveString;

const capabilities: AliasProviderCapabilities = {
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
  connectionId: CONNECTION_ID,
  adapter: { adapterId: "test.adapter", capabilities },
};

const identity = (aliasId = "provider/object:7", connectionId = CONNECTION_ID): AliasIdentity => ({
  version: 1,
  connectionId,
  aliasId,
  address: sensitive("alias@example.test"),
});

const alias = (aliasIdentity = identity(), lifecycle: Alias["lifecycle"] = "enabled"): Alias => ({
  identity: aliasIdentity,
  lifecycle,
  freshness: "current",
  consistency: "clean",
  label: undefined,
  capabilities,
});

const successfulAdapter = (): AliasProviderAdapter => ({
  create: async () => ({ status: "success", value: alias() }),
  list: async () => ({
    status: "success",
    value: { aliases: [alias()], nextPageToken: undefined },
  }),
  get: async (value) => ({ status: "success", value: alias(value) }),
  setEnabled: async (value, enabled) => ({
    status: "success",
    value: alias(value, enabled ? "enabled" : "disabled"),
  }),
  delete: async (value) => ({
    status: "success",
    value: { identity: value, deleted: true },
  }),
  createSendReplyIdentity: async ({ alias: aliasIdentity, recipient }) => ({
    status: "success",
    value: {
      alias: aliasIdentity,
      identityId: "reply/object:9",
      recipient,
      address: sensitive("reply@example.test"),
      valid: true,
      blocked: false,
    },
  }),
  listSendReplyIdentities: async (aliasIdentity) => ({
    status: "success",
    value: {
      identities: [
        {
          alias: aliasIdentity,
          identityId: "reply/object:9",
          recipient: sensitive("recipient@example.test"),
          address: sensitive("reply@example.test"),
          valid: true,
          blocked: false,
        },
      ],
      nextPageToken: undefined,
    },
  }),
  removeSendReplyIdentity: async () => ({ status: "success", value: null }),
  setSendReplyBlocked: async (reply, blocked) => ({
    status: "success",
    value: { ...reply, blocked },
  }),
});

test("executes the complete lifecycle through the injected neutral adapter", async () => {
  const client = new AliasClient(connection, successfulAdapter());
  expect(client.connection()).toEqual(connection);

  const created = await client.create({ hostname: sensitive("example.test") });
  expect(created.identity.aliasId).toBe("provider/object:7");
  expect((await client.list({ pageToken: undefined })).aliases).toEqual([created]);
  expect(await client.get(created.identity)).toEqual(created);
  expect((await client.set_enabled(created.identity, false)).lifecycle).toBe("disabled");

  const reply = await client.create_send_reply_identity({
    alias: created.identity,
    recipient: sensitive("recipient@example.test"),
  });
  expect(reply.identityId).toBe("reply/object:9");
  expect((await client.list_send_reply_identities(created.identity, undefined)).identities).toEqual(
    [reply],
  );
  const blocked = await client.set_send_reply_blocked(reply, true);
  expect(blocked).toEqual({ ...reply, blocked: true });
  await client.remove_send_reply_identity(blocked);
  expect((await client.delete(created.identity)).deleted).toBe(true);
  client.free();
});

test("rejects foreign identities before dispatch", async () => {
  const adapter = successfulAdapter();
  const get = adapter.get;
  let dispatches = 0;
  adapter.get = async (identity) => {
    dispatches += 1;
    return get(identity);
  };
  const client = new AliasClient(connection, adapter);

  await expect(
    client.get(identity("provider/object:7", FOREIGN_CONNECTION_ID)),
  ).rejects.toMatchObject({
    name: "permission-denied",
  });
  expect(dispatches).toBe(0);
  client.free();
});

test("rejects malformed adapter output and never renders provider-owned text", async () => {
  const secret = "provider-body-secret";
  const wrongConnection = successfulAdapter();
  wrongConnection.get = async () => ({
    status: "success",
    value: alias(identity("provider/object:7", FOREIGN_CONNECTION_ID)),
  });
  const invalidClient = new AliasClient(connection, wrongConnection);
  await expect(invalidClient.get(identity())).rejects.toMatchObject({ name: "invalid-response" });
  invalidClient.free();

  const rejected = successfulAdapter();
  rejected.get = async () => {
    throw new Error(secret);
  };
  const rejectedClient = new AliasClient(connection, rejected);
  let rendered = "";
  try {
    await rejectedClient.get(identity());
  } catch (error) {
    rendered = `${String(error)}\n${error instanceof Error ? error.stack : ""}`;
  }
  expect(rendered).toContain("local-security-failure");
  expect(rendered).not.toContain(secret);
  rejectedClient.free();
});

test("maps only the stable callback error taxonomy", async () => {
  const adapter = successfulAdapter();
  adapter.get = async () => ({
    status: "failure",
    failure: { code: "outcome-unknown", retryAfterSeconds: undefined },
  });
  const client = new AliasClient(connection, adapter);
  await expect(client.get(identity())).rejects.toMatchObject({ name: "outcome-unknown" });
  client.free();
});

test("normalizes the only browsing and recipient context before dispatch", async () => {
  const adapter = successfulAdapter();
  let observedHostname = "";
  let observedRecipient = "";
  adapter.create = async (request) => {
    observedHostname = request.hostname ?? "";
    return { status: "success", value: alias() };
  };
  adapter.createSendReplyIdentity = async (request) => {
    observedRecipient = request.recipient;
    return {
      status: "success",
      value: {
        alias: request.alias,
        identityId: "reply/object:9",
        recipient: request.recipient,
        address: sensitive("reply@example.test"),
        valid: true,
        blocked: false,
      },
    };
  };
  const client = new AliasClient(connection, adapter);
  const created = await client.create({ hostname: sensitive("  EXAMPLE.TEST. ") });
  await client.create_send_reply_identity({
    alias: created.identity,
    recipient: sensitive(" Recipient@Example.TEST "),
  });
  expect(observedHostname).toBe("example.test");
  expect(observedRecipient).toBe("recipient@example.test");
  client.free();
});

test("rejects a changed identity snapshot or provider-owned label in adapter output", async () => {
  const wrongResource = successfulAdapter();
  wrongResource.get = async () => ({
    status: "success",
    value: alias(identity("provider/object:other")),
  });
  const wrongResourceClient = new AliasClient(connection, wrongResource);
  await expect(wrongResourceClient.get(identity())).rejects.toMatchObject({
    name: "invalid-response",
  });
  wrongResourceClient.free();

  const injectedLabel = successfulAdapter();
  injectedLabel.get = async () => ({
    status: "success",
    value: { ...alias(), label: sensitive("provider-owned-label") },
  });
  const injectedLabelClient = new AliasClient(connection, injectedLabel);
  await expect(injectedLabelClient.get(identity())).rejects.toMatchObject({
    name: "invalid-response",
  });
  injectedLabelClient.free();

  const changedAddress = successfulAdapter();
  changedAddress.get = async (requested) => ({
    status: "success",
    value: alias({ ...requested, address: sensitive("changed@example.test") }),
  });
  const changedAddressClient = new AliasClient(connection, changedAddress);
  await expect(changedAddressClient.get(identity())).rejects.toMatchObject({
    name: "invalid-response",
  });
  changedAddressClient.free();
});

test("rejects stale or conflicted adapter observations", async () => {
  const stale = successfulAdapter();
  stale.get = async (requested) => ({
    status: "success",
    value: { ...alias(requested), freshness: "stale" },
  });
  const staleClient = new AliasClient(connection, stale);
  await expect(staleClient.get(identity())).rejects.toMatchObject({ name: "invalid-response" });
  staleClient.free();

  const conflicted = successfulAdapter();
  conflicted.list = async () => ({
    status: "success",
    value: {
      aliases: [{ ...alias(), consistency: "conflicted" }],
      nextPageToken: undefined,
    },
  });
  const conflictedClient = new AliasClient(connection, conflicted);
  await expect(conflictedClient.list({ pageToken: undefined })).rejects.toMatchObject({
    name: "invalid-response",
  });
  conflictedClient.free();
});

test("checks optional capability before block dispatch", async () => {
  const baselineCapabilities = { ...capabilities, extensions: [] };
  const baselineConnection: AliasConnection = {
    ...connection,
    adapter: { ...connection.adapter, capabilities: baselineCapabilities },
  };
  const adapter = successfulAdapter();
  let dispatches = 0;
  adapter.setSendReplyBlocked = async (reply, blocked) => {
    dispatches += 1;
    return { status: "success", value: { ...reply, blocked } };
  };
  const client = new AliasClient(baselineConnection, adapter);
  await expect(
    client.set_send_reply_blocked(
      {
        alias: identity(),
        identityId: "reply/object:9",
        recipient: sensitive("recipient@example.test"),
        address: sensitive("reply@example.test"),
        valid: true,
        blocked: undefined,
      },
      true,
    ),
  ).rejects.toMatchObject({ name: "capability-unsupported" });
  expect(dispatches).toBe(0);
  client.free();
});

test("rejects unbounded callback retry metadata", async () => {
  const adapter = successfulAdapter();
  adapter.get = async () => ({
    status: "failure",
    failure: { code: "rate-limited", retryAfterSeconds: 86_401 },
  });
  const client = new AliasClient(connection, adapter);
  await expect(client.get(identity())).rejects.toMatchObject({ name: "invalid-response" });
  client.free();

  const misplaced = successfulAdapter();
  misplaced.get = async () => ({
    status: "failure",
    failure: { code: "permission-denied", retryAfterSeconds: 1 },
  });
  const misplacedClient = new AliasClient(connection, misplaced);
  await expect(misplacedClient.get(identity())).rejects.toMatchObject({
    name: "invalid-response",
  });
  misplacedClient.free();
});
