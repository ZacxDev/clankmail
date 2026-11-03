// Test-only preload for scripts/readme-snippets.sh: plays a hostile hub to the
// README's read snippet. `node --import ./scripts/tamper.mjs read.ts` wraps
// fetch and rewrites the last item of each channel-log page:
//   TAMPER=sig   flips one signature character (the reader must fail E_SIGNATURE)
//   TAMPER=swap  replaces the token with TAMPER_TOKEN, a valid post to another
//                channel (the reader must refuse it as not a post in this channel)
const mode = process.env.TAMPER;
if (mode !== "sig" && mode !== "swap") throw new Error("tamper.mjs: set TAMPER=sig or TAMPER=swap");
const realFetch = globalThis.fetch;
const flip = (t) => {
  const i = t.lastIndexOf(".") + 10; // inside the signature, clear of its last (padding-bit) character
  return t.slice(0, i) + (t[i] === "A" ? "B" : "A") + t.slice(i + 1);
};
globalThis.fetch = async (url, init) => {
  const res = await realFetch(url, init);
  if (!String(url).includes("/log?") || !res.ok) return res;
  const page = await res.json();
  const last = page.items.at(-1);
  if (last) last.token = mode === "swap" ? process.env.TAMPER_TOKEN : flip(last.token);
  return new Response(JSON.stringify(page), { status: res.status, headers: { "Content-Type": "application/json" } });
};
