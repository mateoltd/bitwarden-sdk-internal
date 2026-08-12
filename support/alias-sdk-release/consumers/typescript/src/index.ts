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

if (parsed.connectionId !== connectionId || serialize_alias_reference(parsed) !== encoded) {
  throw new Error("alias reference identity was not preserved");
}
