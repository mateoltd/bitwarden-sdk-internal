import {
  Alias,
  AliasId,
  AliasProviderIdentity,
  CipherId,
  CipherRepromptType,
  CipherType,
  CipherView,
  FieldType,
  SensitiveString,
  apply_alias_reconciliation,
  bind_alias_reference,
  create_alias_reference,
  migrate_alias_reference,
  migrate_cipher_alias_reference,
  parse_alias_reference,
  plan_alias_reconciliation,
  serialize_alias_reference,
} from "@bitwarden/sdk-internal";
import { readFileSync } from "node:fs";

type ConformanceVectors = {
  referenceSchema: {
    vaultFieldName: string;
    credentialSentinel: string;
  };
  identities: {
    primary: { instance: string; connectionId: string };
    sameOriginSecondAccount: { instance: string; connectionId: string };
  };
  referenceVectors: Array<{
    identity: string;
    aliasId: number;
    address: string;
    expectedCanonical: string;
  }>;
  migrationVectors: Array<{
    name: string;
    input: string;
    expectedCanonical?: string;
  }>;
};

const conformance = JSON.parse(
  readFileSync(
    new URL("../../../../../formal/alias-security/conformance-vectors.json", import.meta.url),
    "utf8",
  ),
) as ConformanceVectors;

const CONNECTION_ONE = conformance.identities.primary.connectionId;
const CONNECTION_TWO = conformance.identities.sameOriginSecondAccount.connectionId;
const INSTANCE = conformance.identities.primary.instance;
const REFERENCE_FIELD = conformance.referenceSchema.vaultFieldName;
const NOW = "2026-08-11T10:00:00Z";

const sensitive = (value: string): SensitiveString => value as SensitiveString;
const cipherId = (index: number): CipherId =>
  `00000000-0000-4000-8000-${index.toString(16).padStart(12, "0")}` as CipherId;

const identity = (connectionId: string, instance = INSTANCE): AliasProviderIdentity => ({
  provider: "simplelogin",
  instance,
  connectionId,
});

const alias = (id: number, address: string): Alias => ({
  id: BigInt(id) as AliasId,
  email: sensitive(address),
  creation_date: NOW,
  creation_timestamp: 1n,
  enabled: true,
  note: undefined,
  name: undefined,
  nb_forward: 0n,
  nb_block: 0n,
  nb_reply: 0n,
  mailbox: { id: 1n, email: sensitive("owner@example.test") },
  mailboxes: [{ id: 1n, email: sensitive("owner@example.test") }],
  support_pgp: false,
  disable_pgp: false,
  latest_activity: undefined,
  pinned: false,
});

const cipher = (
  index: number,
  username: string,
  fields: CipherView["fields"] = [],
): CipherView => ({
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
  fields,
  passwordHistory: undefined,
  creationDate: NOW,
  deletedDate: undefined,
  revisionDate: NOW,
  archivedDate: undefined,
});

test("uses one canonical connection-scoped reference across the WASM boundary", () => {
  const referenceVector = conformance.referenceVectors[0];
  const provider = identity(CONNECTION_ONE);
  const providerAlias = alias(referenceVector.aliasId, referenceVector.address);
  const encoded = create_alias_reference(provider, providerAlias);

  expect(encoded).toBe(referenceVector.expectedCanonical);
  expect(encoded).not.toContain(conformance.referenceSchema.credentialSentinel);
  const parsed = parse_alias_reference(encoded);
  expect(parsed.connectionId).toBe(CONNECTION_ONE);
  expect(parsed.aliasId).toBe(BigInt(referenceVector.aliasId));
  expect(serialize_alias_reference(parsed)).toBe(encoded);

  const bound = bind_alias_reference(encoded, cipher(1, "first@example.test"));
  expect(bound.changed).toBe(true);
  expect(bound.cipher.fields).toEqual([
    { name: REFERENCE_FIELD, value: encoded, type: FieldType.Hidden, linkedId: undefined },
  ]);
  expect(bind_alias_reference(encoded, bound.cipher).changed).toBe(false);
});

test("isolates overlapping provider IDs for two accounts on one origin", () => {
  const firstAlias = alias(7, "first@example.test");
  const secondAlias = alias(7, "second@example.test");
  const firstReference = create_alias_reference(identity(CONNECTION_ONE), firstAlias);
  const secondReference = create_alias_reference(identity(CONNECTION_TWO), secondAlias);
  const ciphers = [
    bind_alias_reference(firstReference, cipher(1, "first@example.test")).cipher,
    bind_alias_reference(secondReference, cipher(2, "second@example.test")).cipher,
  ];

  const firstPlan = plan_alias_reconciliation(identity(CONNECTION_ONE), [firstAlias], ciphers);
  expect(firstPlan.summary.matched).toBe(1n);
  expect(firstPlan.summary.skippedCiphers).toBe(1n);
  expect(firstPlan.outcomes).toContainEqual({
    status: "skippedCipher",
    cipher_id: cipherId(2),
    reason: "foreign_provider",
  });

  const secondPlan = plan_alias_reconciliation(identity(CONNECTION_TWO), [secondAlias], ciphers);
  expect(secondPlan.summary.matched).toBe(1n);
  expect(secondPlan.summary.skippedCiphers).toBe(1n);
});

test("requires explicit, unambiguous v1 migration and rewrites the reserved field", () => {
  const migrationVector = conformance.migrationVectors.find(
    (vector) => vector.name === "legacy-unique-connection",
  );
  expect(migrationVector).toBeDefined();
  const legacy = migrationVector!.input;

  expect(() => parse_alias_reference(sensitive(legacy))).toThrow("explicit connection migration");
  expect(() =>
    migrate_alias_reference(sensitive(legacy), [
      identity(CONNECTION_ONE),
      identity(CONNECTION_TWO),
    ]),
  ).toThrow("matches multiple provider connections");

  const migrated = migrate_alias_reference(sensitive(legacy), [identity(CONNECTION_ONE)]);
  expect(migrated).toBe(migrationVector!.expectedCanonical);
  expect(parse_alias_reference(migrated).connectionId).toBe(CONNECTION_ONE);
  expect(migrate_alias_reference(migrated, [identity(CONNECTION_TWO)])).toBe(migrated);

  const legacyCipher = cipher(3, "legacy@example.test", [
    { name: REFERENCE_FIELD, value: legacy, type: FieldType.Hidden, linkedId: undefined },
  ]);
  const output = migrate_cipher_alias_reference(legacyCipher, [identity(CONNECTION_ONE)]);
  expect(output.migration.changed).toBe(true);
  expect(output.migration.reference?.connectionId).toBe(CONNECTION_ONE);
  expect(output.cipher.fields?.[0].value).toBe(migrated);
});

test("safely classifies malformed, duplicate, oversized, and visible reserved fields", () => {
  const malformed = cipher(10, "malformed@example.test", [
    { name: REFERENCE_FIELD, value: "{", type: FieldType.Hidden, linkedId: undefined },
  ]);
  const duplicate = cipher(11, "duplicate@example.test", [
    { name: REFERENCE_FIELD, value: "{}", type: FieldType.Hidden, linkedId: undefined },
    { name: REFERENCE_FIELD, value: "{}", type: FieldType.Hidden, linkedId: undefined },
  ]);
  const oversized = cipher(12, "oversized@example.test", [
    { name: REFERENCE_FIELD, value: "x".repeat(4097), type: FieldType.Hidden, linkedId: undefined },
  ]);
  const visible = cipher(13, "visible@example.test", [
    { name: REFERENCE_FIELD, value: "{}", type: FieldType.Text, linkedId: undefined },
  ]);

  const plan = plan_alias_reconciliation(
    identity(CONNECTION_ONE),
    [],
    [malformed, duplicate, oversized, visible],
  );
  expect(plan.summary.skippedCiphers).toBe(4n);
  expect(plan.actions).toHaveLength(0);
  expect(
    plan.outcomes.map((outcome) => outcome.status === "skippedCipher" && outcome.reason),
  ).toEqual(
    expect.arrayContaining([
      "malformed_reference",
      "duplicate_reference_fields",
      "reference_too_large",
      "reference_field_not_hidden",
    ]),
  );
});

test("plans and applies 10,000 real CipherView values idempotently", () => {
  const count = 10_000;
  const aliases = Array.from({ length: count }, (_, index) =>
    alias(index + 1, `alias-${index + 1}@example.test`),
  );
  const ciphers = aliases.map((providerAlias, index) =>
    cipher(index + 1, providerAlias.email as string),
  );

  const plan = plan_alias_reconciliation(identity(CONNECTION_ONE), aliases, ciphers);
  expect(plan.summary.matchedByAddress).toBe(BigInt(count));
  expect(plan.summary.proposedRepairs).toBe(BigInt(count));

  const applied = apply_alias_reconciliation(plan, aliases, ciphers);
  expect(applied.result.changedCipherIds).toHaveLength(count);
  expect(applied.ciphers).toHaveLength(count);
  const repeatedPlan = plan_alias_reconciliation(
    identity(CONNECTION_ONE),
    aliases,
    applied.ciphers,
  );
  expect(repeatedPlan.summary.matched).toBe(BigInt(count));
  expect(repeatedPlan.actions).toHaveLength(0);
});
