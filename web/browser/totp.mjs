import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Credentials the disposable server's break-glass accounts were created with (server.mjs).
export const accountsFile = fileURLToPath(new URL('../../.browser/breakglass.json', import.meta.url));
export const adminState = fileURLToPath(new URL('../../.browser/admin-state.json', import.meta.url));
export const accounts = () => JSON.parse(readFileSync(accountsFile, 'utf8'));

// RFC 6238 code for a base32 secret, offset by whole 30-second steps.
export function totp(secret, offset = 0) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const c of secret.replace(/=+$/, '')) bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
  const key = Buffer.from(bits.match(/.{8}/g).map(b => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000) + offset));
  const h = createHmac('sha1', key).update(counter).digest();
  const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1000000).padStart(6, '0');
}
