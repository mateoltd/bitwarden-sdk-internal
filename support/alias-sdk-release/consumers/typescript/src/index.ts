import {
  Alias,
  AliasId,
  AliasProviderIdentity,
  SensitiveString,
  create_alias_reference,
  parse_alias_reference,
  serialize_alias_reference,
} from "@bitwarden/sdk-internal";

const connectionId = "11111111-1111-4111-8111-111111111111";
const identity: AliasProviderIdentity = {
  provider: "simplelogin",
  instance: "https://aliases.example.test/",
  connectionId,
};
const sensitive = (value: string): SensitiveString => value as SensitiveString;
const mailbox = { id: BigInt(1), email: sensitive("owner@example.test") };
const providerAlias: Alias = {
  id: BigInt(7) as AliasId,
  email: sensitive("alias@example.test"),
  creation_date: "2026-08-12T00:00:00Z",
  creation_timestamp: BigInt(1),
  enabled: true,
  note: undefined,
  name: undefined,
  nb_forward: BigInt(0),
  nb_block: BigInt(0),
  nb_reply: BigInt(0),
  mailbox,
  mailboxes: [mailbox],
  support_pgp: false,
  disable_pgp: false,
  latest_activity: undefined,
  pinned: false,
};

const encoded = create_alias_reference(identity, providerAlias);
const parsed = parse_alias_reference(encoded);
const expected =
  `{"version":1,"provider":"simplelogin",` +
  `"providerInstance":"https://aliases.example.test/","connectionId":"${connectionId}",` +
  `"aliasId":7,"address":"alias@example.test"}`;

if (
  encoded !== expected ||
  parsed.version !== 1 ||
  parsed.connectionId !== connectionId ||
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
