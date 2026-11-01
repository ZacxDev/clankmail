// Minimal ambient type declarations for Node.js built-ins.
// Since @types/node is not installed (zero-dependency requirement),
// this provides enough typing for tsc --noEmit to check everything else.

interface Buffer extends Uint8Array {
  subarray(start?: number, end?: number): Buffer;
  equals(other: Uint8Array): boolean;
  toString(encoding?: string): string;
  length: number;
  [index: number]: number;
}

interface BufferConstructor {
  from(data: string, encoding?: string): Buffer;
  from(data: Uint8Array | ArrayBuffer): Buffer;
  from(data: readonly number[]): Buffer;
  concat(buffers: readonly Uint8Array[]): Buffer;
  byteLength(s: string, encoding?: string): number;
  alloc(size: number): Buffer;
}

declare var Buffer: BufferConstructor;

declare var process: {
  argv: string[];
  exit(code: number): never;
};

declare module "node:crypto" {
  function createPrivateKey(options: { key: string | Buffer; format: string; type: string }): {
    export(options: { format: string; type: string }): Buffer;
  };
  function createPublicKey(keyOrOptions: object): {
    export(options: { format: string; type: string }): Buffer;
  };
  function createHash(algorithm: string): {
    update(data: Buffer | string): { digest(): Buffer };
  };
  function randomBytes(size: number): Buffer;
  function sign(algorithm: string | null, data: Buffer, key: object): Buffer;
  function verify(algorithm: string | null, data: Buffer, key: object, signature: Buffer): boolean;
}

declare module "node:fs" {
  function readFileSync(path: string, encoding: string): string;
}
