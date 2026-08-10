import {
  AliasClient,
  AliasId,
  ContactId,
  CustomDomainUpdateRequest,
  OptionalSensitiveStringUpdate,
  SensitiveString,
} from "@bitwarden/sdk-internal";
import { runInThisContext } from "node:vm";

const baseUrl = process.env.SIMPLELOGIN_API_URL;
const apiToken = process.env.SIMPLELOGIN_API_TOKEN;
const liveTest = baseUrl && apiToken ? test : test.skip;

// SensitiveString is a compile-time brand over the string value accepted by the WASM ABI.
const sensitive = (value: string): SensitiveString => value as SensitiveString;
const setText = (value: string): OptionalSensitiveStringUpdate => ({
  type: "set",
  value: sensitive(value),
});

liveTest(
  "executes the complete alias lifecycle against real SimpleLogin",
  async () => {
    // Jest's VM sandbox does not inherit Node's web globals. Install the host-realm implementations
    // so this remains a real fetch/stream test rather than replacing transport with a mock.
    Object.assign(
      globalThis,
      runInThisContext(
        "({ fetch, Headers, Request, Response, ReadableStream, ReadableStreamDefaultReader })",
      ),
    );

    const unique = `${Date.now()}-${Math.floor(Math.random() * 1_000_000)}`;
    const hostname = `wasm-${unique}.integration.test`;
    const searchText = `wasm-live-${unique}`;
    const client = new AliasClient({ base_url: baseUrl!, api_token: sensitive(apiToken!) });
    const aliasIds: AliasId[] = [];
    let contactId: ContactId | undefined;

    try {
      const options = await client.get_alias_options(sensitive(hostname));
      expect(options.can_create).toBe(true);
      expect(options.suffixes.length).toBeGreaterThan(0);

      const mailboxes = await client.list_mailboxes();
      const mailbox =
        mailboxes.find((candidate) => candidate.verified && candidate.default) ??
        mailboxes.find((candidate) => candidate.verified);
      expect(mailbox).toBeDefined();

      const alias = await client.create_random_alias({
        hostname: sensitive(hostname),
        mode: undefined,
        note: sensitive(searchText),
      });
      aliasIds.push(alias.id);
      expect(typeof alias.id).toBe("bigint");

      const listed = await client.list_aliases(0);
      expect(listed.aliases.some((candidate) => candidate.id === alias.id)).toBe(true);
      const searched = await client.search_aliases({
        query: sensitive(searchText),
        page: 0,
        filter: undefined,
      });
      expect(searched.aliases.some((candidate) => candidate.id === alias.id)).toBe(true);
      expect((await client.get_alias(alias.id)).email).toBe(alias.email);

      const updated = await client.update_alias(alias.id, {
        note: setText(`updated-${searchText}`),
        name: setText("WASM live alias"),
        mailbox_ids: undefined,
        disable_pgp: undefined,
        pinned: true,
      });
      expect(updated.id).toBe(alias.id);
      expect(updated.name).toBe("WASM live alias");
      expect(updated.pinned).toBe(true);

      const cleared = await client.update_alias(alias.id, {
        note: { type: "clear" },
        name: undefined,
        mailbox_ids: undefined,
        disable_pgp: undefined,
        pinned: undefined,
      });
      expect(cleared.note).toBeUndefined();

      expect((await client.disable_alias(alias.id)).enabled).toBe(false);
      expect((await client.enable_alias(alias.id)).enabled).toBe(true);
      expect((await client.set_alias_enabled(alias.id, true)).enabled).toBe(true);
      expect((await client.get_alias_recommendation(sensitive(hostname)))?.alias).toBe(alias.email);

      const reverse = await client.create_reverse_alias(
        alias.id,
        sensitive(`wasm-contact-${unique}@example.net`),
      );
      contactId = reverse.id;
      expect(typeof reverse.id).toBe("bigint");
      expect(
        (await client.list_contacts(alias.id, 0)).contacts.some(
          (candidate) => candidate.id === reverse.id,
        ),
      ).toBe(true);
      expect((await client.list_reverse_aliases(alias.id, 0)).alias_id).toBe(alias.id);
      expect((await client.toggle_contact_blocked(reverse.id)).block_forward).toBe(true);
      expect((await client.delete_contact(reverse.id)).deleted).toBe(true);
      contactId = undefined;

      expect((await client.list_domains()).length).toBeGreaterThan(0);
      const customDomains = await client.list_custom_domains();
      if (customDomains.length > 0) {
        const request: CustomDomainUpdateRequest = {
          catch_all: customDomains[0].catch_all,
          random_prefix_generation: undefined,
          name: undefined,
          mailbox_ids: undefined,
        };
        expect((await client.update_custom_domain(customDomains[0].id, request)).id).toBe(
          customDomains[0].id,
        );
      }

      const suffix = options.suffixes.find((candidate) => !candidate.is_premium);
      expect(suffix).toBeDefined();
      const custom = await client.create_custom_alias({
        alias_prefix: `wasm${Date.now()}`,
        signed_suffix: suffix!.signed_suffix,
        mailbox_ids: [mailbox!.id],
        hostname: undefined,
        note: sensitive("WASM custom alias"),
        name: sensitive("WASM custom"),
      });
      aliasIds.push(custom.id);
      expect(custom.id).not.toBe(alias.id);
    } finally {
      if (contactId !== undefined) {
        await client.delete_contact(contactId).catch(() => undefined);
      }
      for (const id of aliasIds.reverse()) {
        await client.delete_alias(id).catch(() => undefined);
      }
      client.free();
    }
  },
  60_000,
);
