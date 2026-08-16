import {
  Alias,
  AliasIdentity,
  AliasJournal,
  AliasProviderCapabilities,
  CipherId,
  CipherRepromptType,
  CipherType,
  CipherView,
  SensitiveString,
  apply_alias_reconciliation,
  bind_alias_reference,
  canonicalize_alias_journal,
  clear_alias_reference_if_username_changed,
  create_alias_reference,
  merge_alias_journals,
  parse_alias_reference,
  plan_alias_reconciliation,
  reduce_alias_journal,
  serialize_alias_reference,
} from "@bitwarden/sdk-internal";

const CONNECTION_ONE = "11111111-1111-4111-8111-111111111111";
const CONNECTION_TWO = "22222222-2222-4222-8222-222222222222";
const NOW = "2026-08-11T10:00:00Z";

const sensitive = (value: string): SensitiveString => value as SensitiveString;
const cipherId = (index: number): CipherId =>
  `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}` as CipherId;

const capabilities: AliasProviderCapabilities = {
  create: true,
  list: true,
  get: true,
  enableDisable: true,
  delete: true,
  createSendReplyIdentity: true,
  listSendReplyIdentities: true,
  removeSendReplyIdentity: true,
  extensions: [],
};

const identity = (connectionId: string, aliasId: string, address: string): AliasIdentity => ({
  version: 1,
  connectionId,
  aliasId,
  address: sensitive(address),
});

const alias = (connectionId: string, aliasId: string, address: string): Alias => ({
  identity: identity(connectionId, aliasId, address),
  lifecycle: "enabled",
  freshness: "current",
  consistency: "clean",
  label: undefined,
  capabilities,
});

const cipher = (index: number, username: string): CipherView => ({
  id: cipherId(index),
  organizationId: undefined,
  folderId: undefined,
  collectionIds: [],
  key: undefined,
  name: `Alias ${index}`,
  notes: undefined,
  type: CipherType.Login,
  login: {
    username,
    password: undefined,
    aliasReference: undefined,
    passwordRevisionDate: undefined,
    uris: undefined,
    totp: undefined,
    autofillOnPageLoad: undefined,
    fido2Credentials: undefined,
  },
  identity: undefined,
  card: undefined,
  secureNote: undefined,
  sshKey: undefined,
  bankAccount: undefined,
  driversLicense: undefined,
  passport: undefined,
  favorite: false,
  reprompt: CipherRepromptType.None,
  organizationUseTotp: false,
  edit: true,
  permissions: undefined,
  viewPassword: true,
  localData: undefined,
  attachments: undefined,
  attachmentDecryptionFailures: undefined,
  fields: [],
  passwordHistory: undefined,
  creationDate: NOW,
  deletedDate: undefined,
  revisionDate: NOW,
  archivedDate: undefined,
});

test("uses one canonical provider-neutral reference across the WASM boundary", () => {
  const value = identity(CONNECTION_ONE, "remote/object:7", "first@example.test");
  const encoded = create_alias_reference(value);
  const expected =
    `{"version":1,"connectionId":"${CONNECTION_ONE}",` +
    `"aliasId":"remote/object:7","address":"first@example.test"}`;

  expect(encoded).toBe(expected);
  expect(encoded).not.toContain("simplelogin");
  expect(encoded).not.toContain("providerInstance");
  const parsed = parse_alias_reference(encoded);
  expect(parsed).toEqual(value);
  expect(serialize_alias_reference(parsed)).toBe(encoded);

  const bound = bind_alias_reference(encoded, cipher(1, "first@example.test"));
  expect(bound.changed).toBe(true);
  expect(bound.cipher.login?.aliasReference).toBe(encoded);
  expect(bound.cipher.fields).toEqual([]);
  expect(bind_alias_reference(encoded, bound.cipher).changed).toBe(false);
});

test.each([
  '{"connectionId":"11111111-1111-4111-8111-111111111111"}',
  '{"version":0}',
  '{"version":',
  '{"version":2}',
  `{"version":1,"connectionId":"${CONNECTION_ONE}","aliasId":7,"address":"first@example.test"}`,
])("rejects malformed and non-v1 references", (encoded) => {
  expect(() => parse_alias_reference(encoded as SensitiveString)).toThrow();
});

test("isolates the same opaque remote ID across two connections", () => {
  const firstAlias = alias(CONNECTION_ONE, "same-id", "first@example.test");
  const secondAlias = alias(CONNECTION_TWO, "same-id", "second@example.test");
  const firstReference = create_alias_reference(firstAlias.identity);
  const secondReference = create_alias_reference(secondAlias.identity);
  const ciphers = [
    bind_alias_reference(firstReference, cipher(1, "first@example.test")).cipher,
    bind_alias_reference(secondReference, cipher(2, "second@example.test")).cipher,
  ];

  const firstPlan = plan_alias_reconciliation(CONNECTION_ONE, [firstAlias], ciphers);
  expect(firstPlan.summary.matched).toBe(1n);
  expect(firstPlan.summary.skippedCiphers).toBe(1n);

  const secondPlan = plan_alias_reconciliation(CONNECTION_TWO, [secondAlias], ciphers);
  expect(secondPlan.summary.matched).toBe(1n);
  expect(secondPlan.summary.skippedCiphers).toBe(1n);
});

test("clears the first-class binding on username mismatch and preserves login data", () => {
  const original = cipher(3, "first@example.test");
  original.login!.password = "preserved-password";
  original.notes = "preserved notes";
  const encoded = create_alias_reference(
    identity(CONNECTION_ONE, "opaque:clear", "first@example.test"),
  );
  const bound = bind_alias_reference(encoded, original).cipher;
  bound.login!.username = "edited@example.test";

  const cleared = clear_alias_reference_if_username_changed(bound);
  expect(cleared.changed).toBe(true);
  expect(cleared.cipher.login?.aliasReference).toBeUndefined();
  expect(cleared.cipher.login?.username).toBe("edited@example.test");
  expect(cleared.cipher.login?.password).toBe("preserved-password");
  expect(cleared.cipher.notes).toBe("preserved notes");
});

test("reconciliation is deterministic, scoped, and idempotent", () => {
  const remote = alias(CONNECTION_ONE, "non-numeric/key", "current@example.test");
  const oldIdentity = identity(CONNECTION_ONE, "non-numeric/key", "old@example.test");
  const bound = bind_alias_reference(
    create_alias_reference(oldIdentity),
    cipher(4, "old@example.test"),
  ).cipher;
  bound.notes = "unrelated";

  const plan = plan_alias_reconciliation(CONNECTION_ONE, [remote], [bound]);
  expect(plan.summary.staleBindings).toBe(1n);
  expect(plan.summary.proposedRepairs).toBe(1n);

  const applied = apply_alias_reconciliation(plan, [remote], [bound]);
  expect(applied.result.changedCipherIds).toEqual([cipherId(4)]);
  expect(applied.ciphers[0].notes).toBe("unrelated");
  expect(applied.ciphers[0].login?.username).toBe("current@example.test");
  expect(applied.ciphers[0].login?.aliasReference).toBe(create_alias_reference(remote.identity));

  const repeated = plan_alias_reconciliation(CONNECTION_ONE, [remote], applied.ciphers);
  expect(repeated.summary.matched).toBe(1n);
  expect(repeated.actions).toHaveLength(0);
});

test("journal canonicalization, merge, and reduction preserve a delete tombstone", () => {
  const target = identity(CONNECTION_ONE, "opaque/tombstone", "deleted@example.test");
  const deleteJournal: AliasJournal = {
    version: 1,
    connectionId: CONNECTION_ONE,
    events: [
      {
        version: 1,
        eventId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
        operationId: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        replicaId: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        sequence: 1n,
        causal: [],
        operation: "delete",
        phase: "acknowledged",
        target,
        lifecycle: "deleted",
        error: undefined,
      },
    ],
  };
  const empty: AliasJournal = { version: 1, connectionId: CONNECTION_ONE, events: [] };

  const canonical = canonicalize_alias_journal(deleteJournal);
  const merged = merge_alias_journals(empty, canonical);
  expect(merge_alias_journals(canonical, empty)).toEqual(merged);
  expect(merge_alias_journals(merged, merged)).toEqual(merged);

  const state = reduce_alias_journal(merged);
  expect(state.operations).toHaveLength(1);
  expect(state.operations[0].phase).toBe("acknowledged");
  expect(state.resources).toHaveLength(1);
  expect(state.resources[0].identity.aliasId).toBe("opaque/tombstone");
  expect(state.resources[0].tombstoned).toBe(true);
  expect(state.conflicts).toEqual([]);
});
