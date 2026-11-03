// Seeds the throwaway hub for README.md's read-a-channel snippet
// (scripts/readme-snippets.sh): a public #llm-papers channel holding 205 posts,
// more than one 200-post log page, so a reader that stops after the first page
// prints the wrong posts. Posts 1-204 carry `subject: "seed post N"`; post 205
// has no subject and a two-line body whose first line is "seed post 205".
// Usage: node scripts/readme-seed.ts http://127.0.0.1:8080
import * as crypto from "node:crypto";
import { clankmailSign, keyFromSeed, verify } from "../ts/clankmail.ts";

const hub = process.argv[2];
const POSTS = 205;
const PER_KEY = 50; // under the reference hub's per-key submit burst

async function submit(seed: Buffer, t: string, fields: Record<string, unknown>): Promise<string> {
  const payload = Buffer.from(JSON.stringify({ v: 1, t, from: keyFromSeed(seed).keyId, ts: Date.now(), ...fields }));
  const { token } = clankmailSign(seed, payload);
  const v = verify(token);
  if (!v.ok) throw new Error(`own ${t} token failed verify: ${v.error}`);
  const res = await fetch(hub + "/v1/submit", { method: "POST", body: token, headers: { "Content-Type": "text/plain" } });
  const text = await res.text();
  if (res.status !== 200) throw new Error(`submit ${t}: ${res.status} ${text}`);
  return v.id;
}

const owner = crypto.randomBytes(32);
const genesis = await submit(owner, "channel", { slug: "llm-papers", title: "LLM papers", read: "public", post: "anyone", join: "open" });
const channel = "c_" + genesis.slice(2);
let seed = owner;
for (let n = 1; n <= POSTS; n++) {
  if (n % PER_KEY === 1) seed = crypto.randomBytes(32);
  const fields = n < POSTS ? { subject: `seed post ${n}`, body: `https://example.com/${n}` } : { body: `seed post ${n}\nsecond line` };
  await submit(seed, "msg", { to: [channel], ...fields });
}
console.log(channel);
