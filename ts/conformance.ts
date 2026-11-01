// ClankMail v1 — conformance test runner
// Reads vectors/vectors.json (path from argv) and checks every vector.

import * as fs from "node:fs";
import {
  clankmailSign,
  verify,
  computeChannelId,
  computeDigest,
  type DigestPost,
} from "./clankmail.ts";

interface KeyEntry {
  name: string;
  seed: string;
  key: string;
}

interface ValidVector {
  name: string;
  signer: string;
  payload: string;
  payload_b64: string;
  token: string;
  id: string;
  t: string;
  from: string;
}

interface DerivedEntry {
  [name: string]: string;
}

interface InvalidVector {
  name: string;
  why: string;
  token: string;
  error: string;
}

interface DigestPostVector {
  id: string;
  channel: string;
  from: string;
  ts: number;
  re?: string;
  window?: boolean;
  hidden?: boolean;
  banned?: boolean;
}

interface DigestItemVector {
  id: string;
  repliers: number;
  replies: number;
}

interface DigestVector {
  name: string;
  why: string;
  limit: number;
  per_channel: number;
  posts: DigestPostVector[];
  items: DigestItemVector[];
  omitted: number;
}

interface VectorsFile {
  spec: string;
  domain: string;
  keys: KeyEntry[];
  derived: DerivedEntry;
  valid: ValidVector[];
  invalid: InvalidVector[];
  digest: DigestVector[];
}

function main() {
  const args = process.argv.slice(2);
  if (args.length !== 1) {
    console.error("Usage: node ts/conformance.ts <path-to-vectors.json>");
    process.exit(2);
  }

  const path = args[0];
  let raw = "";
  try {
    raw = fs.readFileSync(path, "utf8");
  } catch {
    console.error(`Cannot read vectors file: ${path}`);
    process.exit(2);
  }

  let dataV: VectorsFile | null = null;
  try {
    dataV = JSON.parse(raw) as VectorsFile;
  } catch {
    console.error("Cannot parse vectors file as JSON");
    process.exit(2);
  }
  const data = dataV!;

  if (data.spec !== "clankmail/v1") {
    console.error("Unknown vectors spec version");
    process.exit(2);
  }

  // Build key map
  const keys = new Map<string, KeyEntry>();
  for (const k of data.keys) {
    keys.set(k.name, k);
  }

  let failures: string[] = [];
  const validCount = data.valid?.length ?? 0;
  const invalidCount = data.invalid?.length ?? 0;

  // Each category on its own: one emptied category must not pass over the others.
  const derivedCount = Object.keys(data.derived ?? {}).length;
  const digestCount = data.digest?.length ?? 0;
  if (validCount === 0 || invalidCount === 0 || derivedCount === 0 || keys.size === 0 || digestCount === 0) {
    console.error(`Vector file has an empty category (keys=${keys.size} valid=${validCount} invalid=${invalidCount} derived=${derivedCount} digest=${digestCount})`);
    process.exit(2);
  }

  const totalVectors = validCount + invalidCount + digestCount;

  // Check valid vectors
  for (const v of data.valid ?? []) {
    // 1. Verify pipeline returns expected id, t, from
    const result = verify(v.token);
    if (!result.ok) {
      failures.push(`${v.name}: expected verification OK, got error ${result.error}`);
      continue;
    }
    if (result.id !== v.id) {
      failures.push(`${v.name}: expected id ${v.id}, got ${result.id}`);
    }
    if (result.t !== v.t) {
      failures.push(`${v.name}: expected t ${v.t}, got ${result.t}`);
    }
    if (result.from !== v.from) {
      failures.push(`${v.name}: expected from ${v.from}, got ${result.from}`);
    }

    // 2. Signer reproduces token byte-for-byte from seed and payload_b64
    const keyEntry = keys.get(v.signer);
    if (!keyEntry) {
      failures.push(`${v.name}: unknown signer "${v.signer}"`);
      continue;
    }
    const seed = Buffer.from(keyEntry.seed, "hex");
    const payloadBytes = Buffer.from(v.payload_b64, "base64");
    
    // Check that the payload_b64 round-trips (verify it's the authoritative bytes)
    const signResult = clankmailSign(seed, payloadBytes);
    if (signResult.token !== v.token) {
      failures.push(`${v.name}: signer reproduction failed`);
    }
  }

  // Check derived values
  for (const [name, expected] of Object.entries(data.derived ?? {})) {
    if (name === "channel-genesis.channel_id") {
      // Compute channel id from the channel-genesis vector's payload_b64
      const genesis = (data.valid ?? []).find(v => v.name === "channel-genesis");
      if (!genesis) {
        failures.push(`${name}: no channel-genesis vector found`);
        continue;
      }
      const genesisPayload = Buffer.from(genesis.payload_b64, "base64");
      
      // Channel id: c_ + same 52 chars as the genesis m_ id
      const got = computeChannelId(genesisPayload);
      if (got !== expected) {
        failures.push(`${name}: expected ${expected}, got ${got}`);
      }
    } else {
      failures.push(`${name}: unknown derived entry`);
    }
  }

  // Check invalid vectors
  for (const v of data.invalid ?? []) {
    const result = verify(v.token);
    if (result.ok) {
      failures.push(`${v.name}: expected error ${v.error}, got OK (id=${result.id})`);
    } else if (result.error !== v.error) {
      failures.push(`${v.name}: expected error ${v.error}, got ${result.error}`);
    }
  }

  // Check digest vectors
  for (const d of data.digest ?? []) {
    const posts: DigestPost[] = d.posts.map(p => ({
      id: p.id,
      channel: p.channel,
      from: p.from,
      ts: p.ts,
      re: p.re,
      window: p.window,
      hidden: p.hidden,
      banned: p.banned,
    }));
    const result = computeDigest(posts, d.limit, d.per_channel);

    // Check items: same count, same ids, same order, same repliers and replies
    if (result.items.length !== d.items.length) {
      failures.push(`${d.name}: expected ${d.items.length} items, got ${result.items.length}`);
      continue;
    }
    for (let i = 0; i < d.items.length; i++) {
      const ei = d.items[i];
      const gi = result.items[i];
      if (ei.id !== gi.id) {
        failures.push(`${d.name}: items[${i}] expected id ${ei.id}, got ${gi.id}`);
      }
      if (ei.repliers !== gi.repliers) {
        failures.push(`${d.name}: items[${i}] expected repliers ${ei.repliers}, got ${gi.repliers}`);
      }
      if (ei.replies !== gi.replies) {
        failures.push(`${d.name}: items[${i}] expected replies ${ei.replies}, got ${gi.replies}`);
      }
    }

    if (result.omitted !== d.omitted) {
      failures.push(`${d.name}: expected omitted ${d.omitted}, got ${result.omitted}`);
    }
  }

  // Print results
  for (const f of failures) {
    console.log(f);
  }

  if (failures.length === 0) {
    console.log(`ts: ${totalVectors} passed`);
    process.exit(0);
  } else {
    console.log(`ts: ${failures.length}/${totalVectors} failed`);
    process.exit(1);
  }
}

main();
