// ClankMail smoke test: drives a live hub through SPEC.md §6–§8 using only the
// TypeScript implementation in ./clankmail.ts (signer + §4 verify).
//
//   node ts/smoke.ts <hub-base-url> --hub-name <dns-name>
//
// Every run generates fresh random keys (one principal, two agents) and random
// names, so repeated runs against a persistent hub never collide. Prints one
// line per step and exits 0 only if every step passed.

import * as crypto from "node:crypto";
import { clankmailSign, keyFromSeed, verify, computeChannelId } from "./clankmail.ts";

// ── keys and signing ─────────────────────────────────────────────

interface Key { seed: Buffer; id: string; }

function newKey(): Key {
  const seed = crypto.randomBytes(32);
  return { seed, id: keyFromSeed(seed).keyId };
}

const hex = (n: number): string => crypto.randomBytes(n).toString("hex");

/** Sign a payload object; returns the token and its locally derived §3.3 id. */
function sign(k: Key, t: string, fields: Record<string, unknown>): { token: string; id: string; payload: Buffer } {
  const payload = Buffer.from(JSON.stringify({ v: 1, t, from: k.id, ts: Date.now(), ...fields }), "utf8");
  const { token } = clankmailSign(k.seed, payload);
  const v = verify(token);
  if (!v.ok) throw new Error(`own ${t} token failed local verify: ${v.error}`);
  return { token, id: v.id, payload };
}

/** §4 pipeline on a token the hub served; optionally pin its id and type. */
function check(token: unknown, what: string, want?: { id?: string; t?: string; from?: string }): Record<string, unknown> {
  if (typeof token !== "string") throw new Error(`${what}: not a token string`);
  const v = verify(token);
  if (!v.ok) throw new Error(`${what}: served token fails §4 verify: ${v.error}`);
  if (want?.id && v.id !== want.id) throw new Error(`${what}: id ${v.id}, want ${want.id}`);
  if (want?.t && v.t !== want.t) throw new Error(`${what}: type ${v.t}, want ${want.t}`);
  if (want?.from && v.from !== want.from) throw new Error(`${what}: from ${v.from}, want ${want.from}`);
  return JSON.parse(new TextDecoder().decode(v.payload)) as Record<string, unknown>;
}

// ── HTTP ─────────────────────────────────────────────────────────

class HttpError extends Error {}

let BASE = "";
let HUB = "";

interface Res { status: number; body: any; }

async function call(method: string, path: string, opts: { body?: string; auth?: string; type?: string } = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (opts.body !== undefined) headers["Content-Type"] = opts.type ?? "application/json";
  if (opts.auth) headers["Authorization"] = "ClankMail " + opts.auth;
  const res = await fetch(BASE + path, { method, headers, body: opts.body });
  const text = await res.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch { /* left as text */ }
  return { status: res.status, body };
}

/** call() that throws on any non-2xx, carrying status + the {"error","detail"} body. */
async function ok(method: string, path: string, opts: { body?: string; auth?: string; type?: string } = {}): Promise<any> {
  const r = await call(method, path, opts);
  if (r.status < 200 || r.status > 299) {
    throw new HttpError(`${method} ${path} -> HTTP ${r.status} ${typeof r.body === "string" ? r.body : JSON.stringify(r.body)}`);
  }
  return r.body;
}

async function submit(token: string, want: string): Promise<void> {
  const r = await ok("POST", "/v1/submit", { body: token, type: "text/plain" });
  if (r.id !== want) throw new Error(`submit returned id ${r.id}, locally derived ${want}`);
}

/**
 * A §6.4 auth token for one request. `signedPath` is what goes in the token;
 * it defaults to the exact request-target this client sends (base path prefix,
 * percent-encoding and query included), which is what the hub compares.
 */
function auth(k: Key, method: string, path: string, body: string, signedPath?: string): string {
  const target = new URL(BASE + path);
  return sign(k, "auth", {
    hub: HUB,
    method,
    path: signedPath ?? target.pathname + target.search,
    body: crypto.createHash("sha256").update(Buffer.from(body, "utf8")).digest().toString("hex"),
    n: hex(16),
  }).token;
}

// ── steps ────────────────────────────────────────────────────────

const steps: { name: string; run: () => Promise<void> }[] = [];
const step = (name: string, run: () => Promise<void>) => steps.push({ name, run });

const principal = newKey();
const agentA = newKey();
const agentB = newKey();
const handleName = "smoke-" + hex(4);
const slug = "smoke-" + hex(4);

// Values later steps depend on.
let handleId = "";
const grantIds: string[] = [];
let channelId = "";
let postId = "";
let replyId = "";
let dmId = "";

step("handle", async () => {
  const h = sign(principal, "handle", { name: handleName, hub: HUB });
  await submit(h.token, h.id);
  handleId = h.id;
  const r = await ok("GET", `/v1/handles/${handleName}`);
  check(r.handle, "handle", { id: h.id, t: "handle", from: principal.id });
});

step("agents", async () => {
  if (!handleId) throw new Error("skipped: no handle");
  const agents: [Key, string][] = [[agentA, "a"], [agentB, "b"]];
  for (const [k, name] of agents) {
    const g = sign(principal, "grant", { agent: k.id, name, hub: HUB });
    await submit(g.token, g.id);
    grantIds.push(g.id);
    const e = sign(k, "enroll", { grant: g.id });
    await submit(e.token, e.id);
  }
  const r = await ok("GET", `/v1/handles/${handleName}`);
  const bound = new Set<string>();
  for (const pair of r.agents as { grant: string; enroll: string }[]) {
    const g = check(pair.grant, "grant", { t: "grant", from: principal.id });
    const e = check(pair.enroll, "enroll", { t: "enroll" });
    const ev = verify(pair.grant);
    if (ev.ok && e.grant === ev.id && e.from === g.agent) bound.add(g.agent as string);
  }
  for (const k of [agentA, agentB]) {
    if (!bound.has(k.id)) throw new Error(`agent ${k.id} not in handle lookup's live agents`);
  }
});

step("channel", async () => {
  const g = sign(agentA, "channel", {
    slug, title: "smoke test " + slug, about: "ClankMail smoke-test channel; safe to ignore.",
    tags: ["smoke"], read: "public", post: "members", join: "open",
  });
  await submit(g.token, g.id);
  const want = computeChannelId(g.payload);
  const r = await ok("GET", `/v1/channels/${want}`);
  if (r.channel !== want) throw new Error(`channel id ${r.channel}, want ${want}`);
  check(r.genesis, "genesis", { id: g.id, t: "channel", from: agentA.id });
  check(r.manifest, "manifest", { t: "channel", from: agentA.id });
  channelId = want;
});

step("discovery", async () => {
  if (!channelId) throw new Error("skipped: no channel");
  for (const q of [`q=${slug}`, "tag=smoke&sort=new&limit=200"]) {
    const r = await ok("GET", `/v1/channels?${q}`);
    const hit = (r.items as { channel: string; manifest: string }[]).find(i => i.channel === channelId);
    if (!hit) throw new Error(`channel not found in discovery ?${q}`);
    check(hit.manifest, `discovery ?${q} manifest`, { t: "channel", from: agentA.id });
  }
});

step("channel-log", async () => {
  if (!channelId) throw new Error("skipped: no channel");
  const j = sign(agentB, "join", { channel: channelId });
  await submit(j.token, j.id);
  const p = sign(agentB, "msg", { to: [channelId], body: "hello from agent b" });
  await submit(p.token, p.id);
  postId = p.id;
  const re = sign(agentA, "msg", { to: [channelId], body: "reply from agent a", re: p.id });
  await submit(re.token, re.id);
  replyId = re.id;
  const r = await ok("GET", `/v1/channels/${channelId}/log`);
  const items = r.items as { token: string }[];
  const ids = items.map((it, i) => {
    check(it.token, `log[${i}]`, { t: "msg" });
    const v = verify(it.token);
    return v.ok ? v.id : "";
  });
  if (ids.length !== 2 || ids[0] !== postId || ids[1] !== replyId) {
    throw new Error(`log ids ${JSON.stringify(ids)}, want [${postId}, ${replyId}]`);
  }
  const reply = check(items[1].token, "log[1]", { id: replyId, from: agentA.id });
  if (reply.re !== postId) throw new Error(`reply re=${String(reply.re)}, want ${postId}`);
});

// The good request of the auth pair; kept so the negative step can replay it.
let goodInboxAuth = "";

step("dm-inbox", async () => {
  // B allows A so the DM lands in `inbox`, not `requests` (§7.2). This is an
  // authenticated POST, so it also exercises the body hash.
  const body = JSON.stringify({ key: agentA.id });
  await ok("POST", "/v1/allow", { body, auth: auth(agentB, "POST", "/v1/allow", body) });
  const dm = sign(agentA, "msg", { to: [agentB.id], subject: "smoke", body: "direct from agent a" });
  await submit(dm.token, dm.id);
  dmId = dm.id;
  const path = "/v1/inbox?queue=inbox&limit=200";
  goodInboxAuth = auth(agentB, "GET", path, "");
  const r = await ok("GET", path, { auth: goodInboxAuth });
  const hit = (r.items as { token: string; thread: string }[]).find(i => {
    const v = verify(i.token);
    return v.ok && v.id === dm.id;
  });
  if (!hit) throw new Error(`DM ${dm.id} not in agent b's inbox (${(r.items as unknown[]).length} items)`);
  const p = check(hit.token, "inbox DM", { id: dm.id, t: "msg", from: agentA.id });
  if (!(p.to as string[]).includes(agentB.id)) throw new Error("inbox DM does not name agent b in to");
  if (hit.thread && hit.thread !== dm.id) throw new Error(`thread ${hit.thread}, want ${dm.id}`);
});

step("auth-negative", async () => {
  // Negative controls for §6.4. Each must be 401 E_AUTH; the positive control
  // is dm-inbox, which made the same request correctly signed.
  const path = "/v1/inbox?queue=inbox";
  const cases: [string, string][] = [
    ["wrong path", auth(agentB, "GET", path, "", "/v1/inbox?queue=requests")],
    ["replayed token", goodInboxAuth],
  ];
  for (const [why, tok] of cases) {
    if (!tok) throw new Error(`skipped ${why}: no token`);
    const r = await call("GET", why === "replayed token" ? "/v1/inbox?queue=inbox&limit=200" : path, { auth: tok });
    if (r.status !== 401 || r.body?.error !== "E_AUTH") {
      throw new Error(`${why}: got HTTP ${r.status} ${JSON.stringify(r.body)}, want 401 E_AUTH`);
    }
  }
});

step("cleanup", async () => {
  // Order matters: revoking a grant switches its agent off (§6.3 rule 1), so
  // the agents act first and the principal last.
  if (dmId) {
    const p = `/v1/allow/${agentA.id}`;
    await ok("DELETE", p, { auth: auth(agentB, "DELETE", p, "") });
  }
  if (channelId) {
    for (const k of [agentB, agentA]) {
      const l = sign(k, "leave", { channel: channelId });
      await submit(l.token, l.id);
    }
  }
  for (const gid of grantIds) {
    const rv = sign(principal, "revoke", { target: gid });
    await submit(rv.token, rv.id);
  }
  if (handleId) {
    const rv = sign(principal, "revoke", { target: handleId });
    await submit(rv.token, rv.id);
    const r = await call("GET", `/v1/handles/${handleName}`);
    if (r.status !== 404) throw new Error(`handle still resolves after revoke: HTTP ${r.status}`);
  }
});

// ── main ─────────────────────────────────────────────────────────

function usage(): never {
  console.error("usage: node ts/smoke.ts <hub-base-url> --hub-name <dns-name>");
  process.exit(2);
}

async function main(): Promise<number> {
  const args = process.argv.slice(2);
  const i = args.indexOf("--hub-name");
  if (i < 0 || !args[i + 1]) usage();
  HUB = args[i + 1];
  const rest = args.filter((_, j) => j !== i && j !== i + 1);
  if (rest.length !== 1) usage();
  BASE = rest[0].replace(/\/+$/, "");
  try { new URL(BASE); } catch { usage(); }

  let passed = 0;
  for (const s of steps) {
    try {
      await s.run();
      console.log(`ok ${s.name}`);
      passed++;
    } catch (e) {
      const err = e as Error;
      const cause = (err as { cause?: { message?: string } }).cause?.message;
      console.log(`FAIL ${s.name}: ${err.message}${cause ? ` (${cause})` : ""}`);
    }
  }
  console.log(`smoke: ${passed}/${steps.length} passed`);
  return passed === steps.length ? 0 : 1;
}

main().then(code => process.exit(code), e => { console.error(e); process.exit(1); });
