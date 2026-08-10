import { AliasClient, SensitiveString } from "@bitwarden/sdk-internal";
import { runInNewContext, runInThisContext } from "node:vm";

const sensitive = (value: string): SensitiveString => value as SensitiveString;
const token = "wasm-adversarial-token";

const aliasJson = (id: number, enabled: boolean) => ({
  id,
  email: `alias-${id}@sl.test`,
  creation_date: "2026-08-10T10:00:00+00:00",
  creation_timestamp: 1786356000,
  enabled,
  note: null,
  name: null,
  nb_forward: 0,
  nb_block: 0,
  nb_reply: 0,
  mailbox: { id: 11, email: "owner@example.test" },
  mailboxes: [{ id: 11, email: "owner@example.test" }],
  support_pgp: false,
  disable_pgp: false,
  latest_activity: null,
  pinned: false,
});

type FetchDispatch = (request: Request) => Promise<Response> | Response | object;

const hostWebGlobals = runInThisContext(
  "({ fetch, Headers, Request, Response, ReadableStream, ReadableStreamDefaultReader })",
) as Record<string, unknown>;

const installCrossRealmFetch = (dispatch: FetchDispatch): (() => void) => {
  const previous = new Map<string, PropertyDescriptor | undefined>();
  for (const name of Object.keys(hostWebGlobals)) {
    previous.set(name, Object.getOwnPropertyDescriptor(globalThis, name));
  }
  for (const [name, value] of Object.entries(hostWebGlobals)) {
    Object.defineProperty(globalThis, name, { configurable: true, writable: true, value });
  }
  const fetchFromAnotherRealm = runInNewContext("dispatch => request => dispatch(request)")(
    dispatch,
  ) as typeof fetch;
  Object.defineProperty(globalThis, "fetch", {
    configurable: true,
    writable: true,
    value: fetchFromAnotherRealm,
  });

  return () => {
    for (const [name, descriptor] of previous) {
      if (descriptor) {
        Object.defineProperty(globalThis, name, descriptor);
      } else {
        delete (globalThis as unknown as Record<string, unknown>)[name];
      }
    }
  };
};

const newClient = () =>
  new AliasClient({
    base_url: "https://simplelogin.invalid/",
    api_token: sensitive(token),
  });

type ErrorRenderings = {
  string: string;
  message: string;
  stack: string;
  json: string;
};

const captureError = async (operation: Promise<unknown>): Promise<ErrorRenderings> => {
  try {
    await operation;
  } catch (error) {
    const candidate = error as Error;
    return {
      string: String(error),
      message: candidate.message,
      stack: candidate.stack ?? "",
      json: JSON.stringify(error),
    };
  }
  throw new Error("operation unexpectedly succeeded");
};

const renderedError = async (operation: Promise<unknown>): Promise<string> =>
  Object.values(await captureError(operation)).join("\n");

test("rejects authenticated redirects without replaying or leaking credentials", async () => {
  let calls = 0;
  const restore = installCrossRealmFetch((request) => {
    calls += 1;
    expect(request.redirect).toBe("manual");
    expect(request.credentials).toBe("omit");
    expect(request.headers.get("Authentication")).toBe(token);
    return new Response(null, {
      status: 302,
      headers: { Location: "https://attacker.invalid/capture?secret=redirect-secret" },
    });
  });
  const client = newClient();
  try {
    const rendered = await renderedError(client.list_domains());
    expect(rendered).toContain("redirect rejected");
    expect(rendered).not.toContain(token);
    expect(rendered).not.toContain("attacker.invalid");
    expect(rendered).not.toContain("redirect-secret");
    expect(calls).toBe(1);
  } finally {
    client.free();
    restore();
  }
});

test.each([
  [200, 512 * 1024],
  [500, 16 * 1024],
])("cancels and unlocks oversized streamed HTTP %i responses", async (status, limit) => {
  let canceled = 0;
  let stream: ReadableStream<Uint8Array>;
  const restore = installCrossRealmFetch(() => {
    stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(limit + 1));
      },
      cancel() {
        canceled += 1;
      },
    });
    return new Response(stream, {
      status,
      headers: { "Content-Type": "application/json" },
    });
  });
  const client = newClient();
  try {
    const rendered = await renderedError(client.list_domains());
    expect(rendered).toContain(`${limit}-byte limit`);
    expect(rendered).not.toContain(token);
    expect(canceled).toBe(1);
    expect(stream!.locked).toBe(false);
  } finally {
    client.free();
    restore();
  }
});

test("bounds and sanitizes provider errors in every JavaScript rendering", async () => {
  let calls = 0;
  const hostile = `failure ${token}\n<script>alert(1)</script>\u001b[31m\u202espoof ${"x".repeat(700)}`;
  const restore = installCrossRealmFetch(() => {
    calls += 1;
    return new Response(JSON.stringify({ error: hostile }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  });
  const client = newClient();
  try {
    const renderings = await captureError(client.list_domains());
    for (const rendered of Object.values(renderings)) {
      expect(rendered).not.toContain(token);
      expect(rendered).not.toContain("<script>");
      expect(rendered).not.toContain("\u001b");
      expect(rendered).not.toContain("\u202e");
    }
    expect(renderings.message.length).toBeLessThan(700);
    expect(renderings.string.length).toBeLessThan(750);
    expect(renderings.json.length).toBeLessThan(750);
    expect(renderings.stack.length).toBeLessThan(5_000);
    expect(calls).toBe(1);
  } finally {
    client.free();
    restore();
  }
});

test("rejects malformed JSON and structurally invalid fetch responses", async () => {
  let malformed = true;
  const restore = installCrossRealmFetch(() => {
    if (malformed) {
      malformed = false;
      return new Response("{", {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return {};
  });
  const client = newClient();
  try {
    const invalidJson = await renderedError(client.list_domains());
    expect(invalidJson).toContain("invalid alias provider response");
    const invalidFetch = await renderedError(client.list_domains());
    expect(invalidFetch).toContain("provider response status unavailable");
    expect(`${invalidJson}\n${invalidFetch}`).not.toContain(token);
  } finally {
    client.free();
    restore();
  }
});

test("surfaces rate limiting without retrying the request", async () => {
  let calls = 0;
  const restore = installCrossRealmFetch(() => {
    calls += 1;
    return new Response(JSON.stringify({ error: token }), {
      status: 429,
      headers: { "Content-Type": "application/json", "Retry-After": "17" },
    });
  });
  const client = newClient();
  try {
    const rendered = await renderedError(client.list_domains());
    expect(rendered).toContain("rate limit reached");
    expect(rendered).not.toContain(token);
    expect(calls).toBe(1);
  } finally {
    client.free();
    restore();
  }
});

test("serializes concurrent explicit state changes across the WASM boundary", async () => {
  let enabled = true;
  let gets = 0;
  let toggles = 0;
  const restore = installCrossRealmFetch(async (request) => {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/api/aliases/101") {
      gets += 1;
      const observed = enabled;
      await new Promise((resolve) => setTimeout(resolve, 30));
      return new Response(JSON.stringify(aliasJson(101, observed)), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (request.method === "POST" && url.pathname === "/api/aliases/101/toggle") {
      toggles += 1;
      enabled = !enabled;
      return new Response(JSON.stringify({ enabled }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response(JSON.stringify({ error: "unexpected request" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  });
  const firstClient = newClient();
  const secondClient = newClient();
  try {
    const [first, second] = await Promise.all([
      firstClient.disable_alias(101n),
      secondClient.disable_alias(101n),
    ]);
    expect(first.enabled).toBe(false);
    expect(second.enabled).toBe(false);
    expect(enabled).toBe(false);
    expect(gets).toBe(2);
    expect(toggles).toBe(1);
  } finally {
    firstClient.free();
    secondClient.free();
    restore();
  }
});
