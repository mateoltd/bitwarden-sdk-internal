import {
  Alias,
  AliasId,
  AliasProviderIdentity,
  CipherId,
  CipherRepromptType,
  CipherType,
  CipherView,
  SensitiveString,
  apply_alias_reconciliation,
  bind_alias_reference,
  create_alias_reference,
  parse_alias_reference,
  plan_alias_reconciliation,
  serialize_alias_reference,
} from "@bitwarden/sdk-internal";
import { readFileSync } from "node:fs";

type ConformanceVectors = {
  referenceSchema: {
    version: number;
    loginMemberName: string;
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
  rejectedReferenceVectors: Array<{
    name: string;
    encoded: string;
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

test("uses one canonical connection-scoped reference across the WASM boundary", () => {
  const referenceVector = conformance.referenceVectors[0];
  const provider = identity(CONNECTION_ONE);
  const providerAlias = alias(referenceVector.aliasId, referenceVector.address);
  const encoded = create_alias_reference(provider, providerAlias);

  expect(encoded).toBe(referenceVector.expectedCanonical);
  expect(encoded).not.toContain(conformance.referenceSchema.credentialSentinel);
  const parsed = parse_alias_reference(encoded);
  expect(parsed.version).toBe(1);
  expect(conformance.referenceSchema.version).toBe(1);
  expect(parsed.connectionId).toBe(CONNECTION_ONE);
  expect(parsed.aliasId).toBe(BigInt(referenceVector.aliasId));
  expect(serialize_alias_reference(parsed)).toBe(encoded);

  const bound = bind_alias_reference(encoded, cipher(1, "first@example.test"));
  expect(bound.changed).toBe(true);
  expect(bound.cipher.login?.aliasReference).toBe(encoded);
  expect(bound.cipher.fields).toEqual([]);
  expect(bind_alias_reference(encoded, bound.cipher).changed).toBe(false);
});

test.each(conformance.rejectedReferenceVectors)(
  "rejects non-v1 reference vector $name",
  ({ encoded }) => {
    expect(() => parse_alias_reference(encoded)).toThrow();
    expect(() => bind_alias_reference(encoded, cipher(90, "first@example.test"))).toThrow();
  },
);

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

test("does not infer a binding from an address without a current reference", () => {
  const providerAlias = alias(7, "first@example.test");
  const ordinaryLogin = cipher(3, "first@example.test");

  const plan = plan_alias_reconciliation(
    identity(CONNECTION_ONE),
    [providerAlias],
    [ordinaryLogin],
  );

  expect(plan.summary.unboundAliases).toBe(1n);
  expect(plan.summary.proposedRepairs).toBe(0n);
  expect(plan.actions).toHaveLength(0);
});

test("safely classifies malformed, oversized, and future login references", () => {
  const malformed = cipher(10, "malformed@example.test");
  malformed.login!.aliasReference = "{";
  const oversized = cipher(11, "oversized@example.test");
  oversized.login!.aliasReference = "x".repeat(4097);
  const future = cipher(12, "future@example.test");
  future.login!.aliasReference = "{\"version\":999}";

  const plan = plan_alias_reconciliation(
    identity(CONNECTION_ONE),
    [],
    [malformed, oversized, future],
  );
  expect(plan.summary.skippedCiphers).toBe(3n);
  expect(plan.actions).toHaveLength(0);
  expect(
    plan.outcomes.map((outcome) => outcome.status === "skippedCipher" && outcome.reason),
  ).toEqual(
    expect.arrayContaining([
      "malformed_reference",
      "reference_too_large",
      "unsupported_reference_version",
    ]),
  );
});

test("plans and applies 10,000 real CipherView values idempotently", () => {
  const count = 10_000;
  const aliases = Array.from({ length: count }, (_, index) =>
    alias(index + 1, `alias-${index + 1}@example.test`),
  );
  const ciphers = aliases.map((providerAlias, index) => {
    const encoded = create_alias_reference(identity(CONNECTION_ONE), providerAlias);
    const bound = bind_alias_reference(encoded, cipher(index + 1, providerAlias.email as string));
    bound.cipher.login!.username = `stale-${index + 1}@example.test`;
    return bound.cipher;
  });

  const plan = plan_alias_reconciliation(identity(CONNECTION_ONE), aliases, ciphers);
  expect(plan.summary.staleBindings).toBe(BigInt(count));
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
