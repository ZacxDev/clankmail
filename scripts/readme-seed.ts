// Seeds the throwaway hub for README.md's read-a-channel snippet
// (scripts/readme-snippets.sh): a public #llm-papers channel holding 205 posts,
// more than one 200-post log page, so a reader that stops after the first page
// prints the wrong posts. Posts 1-204 carry `subject: "seed post N"`, except
// that 204's subject also holds a NEL (U+0085) and a right-to-left override
// (U+202E), which the reader must print escaped; post 205 has no subject and a
// two-line body whose first line is "seed post 205". Also one post to a second
// channel, #other-papers, whose token is printed: scripts/tamper.mjs swaps it
// into the #llm-papers log to check the reader's channel check.
// Usage: node scripts/readme-seed.ts http://127.0.0.1:8080
import * as crypto from "node:crypto";
import { clankmailSign, keyFromSeed, verify } from "../ts/clankmail.ts";

const hub = process.argv[2];
const POSTS = 205;
const PER_KEY = 50; // under the reference hub's per-key submit burst

async function submit(seed: Buffer, t: string, fields: Record<string, unknown>): Promise<{ id: string; token: string }> {
  const payload = Buffer.from(JSON.stringify({ v: 1, t, from: keyFromSeed(seed).keyId, ts: Date.now(), ...fields }));
  const { token } = clankmailSign(seed, payload);
  const v = verify(token);
  if (!v.ok) throw new Error(`own ${t} token failed verify: ${v.error}`);
  const res = await fetch(hub + "/v1/submit", { method: "POST", body: token, headers: { "Content-Type": "text/plain" } });
  const text = await res.text();
  if (res.status !== 200) throw new Error(`submit ${t}: ${res.status} ${text}`);
  return { id: v.id, token };
}

async function channel(seed: Buffer, slug: string): Promise<string> {
  const g = await submit(seed, "channel", { slug, title: slug, read: "public", post: "anyone", join: "open" });
  return "c_" + g.id.slice(2);
}

const owner = crypto.randomBytes(32);
const papers = await channel(owner, "llm-papers");
const other = await channel(owner, "other-papers");
const stray = await submit(owner, "msg", { to: [other], subject: "seed post in other-papers", body: "https://example.com/other" });
let seed = owner;
for (let n = 1; n <= POSTS; n++) {
  if (n % PER_KEY === 1) seed = crypto.randomBytes(32);
  const subject = n === 204 ? "seed post 204\u0085\u202eevil" : `seed post ${n}`;
  const fields = n < POSTS ? { subject, body: `https://example.com/${n}` } : { body: `seed post ${n}\nsecond line` };
  await submit(seed, "msg", { to: [papers], ...fields });
}
console.log(stray.token);
