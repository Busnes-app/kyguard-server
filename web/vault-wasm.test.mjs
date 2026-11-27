import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const fixture = async (path) => JSON.parse(await readFile(new URL(path, import.meta.url), 'utf8'));
const assets = new URL('./vault-dist/assets/', import.meta.url);
const encode = (object) => Buffer.from(JSON.stringify(object)).toString('base64url');

await import(new URL('wasm_exec.js', assets));
const go = new globalThis.Go();
const wasm = await readFile(new URL('vault-crypto.wasm', assets));
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
void go.run(instance);

function call(action, input = {}) {
  const result = JSON.parse(globalThis.kyGuardVault(JSON.stringify({ action, ...input })));
  if (result.error) throw new Error(result.error);
  return result.value;
}

test('the browser WASM uses the KyIdentity handoff to seal and unlock a KyGuard user key', async () => {
  const vector = await fixture('../internal/vaultclient/testdata/kyidentity-handoff.json');
  const ctx = await fixture('../internal/pqcrypto/testdata/vectors/context.json');
  const trust = {
    fingerprint: ctx.fingerprint,
    bundle: encode(ctx.bundle),
    manifests: ctx.manifests.map(encode),
    heads: {},
  };
  assert.throws(() => call('sync', { trust: { ...trust, fingerprint: '0'.repeat(64) } }), /fingerprint/);
  const seen = call('sync', { trust }).heads;
  assert.throws(() => call('sync', { trust: { ...trust, heads: seen, manifests: [] } }), /older or conflicting/);
  const identity = {
    user_id: 'kyguard-user',
    issuer: vector.handoff.issuer,
    subject: vector.handoff.subject,
    method: 'kyidentity',
  };
  assert.throws(() => call('keyring-open', {
    user_id: identity.user_id, seed: vector.seed, handoff: { ...vector.handoff, nonce: 'different' },
  }), /could not unlock/);
  call('keyring-open', { user_id: identity.user_id, seed: vector.seed, handoff: vector.handoff });
  const bundle = call('new-key', identity);
  assert.equal(bundle.sealed.method, 'kyidentity');
  assert.equal(bundle.sealed.key_version, vector.handoff.key_version);
  assert.equal(bundle.sealed.keyring_version, vector.handoff.keyring_version);
  assert.throws(() => call('unlock', { ...identity, user_id: 'other-user', ...bundle }), /sign in with the KyIdentity keyring/);
  call('unlock', { ...identity, ...bundle });
  call('lock');
});

test('the browser WASM also unlocks with a separate passphrase', async () => {
  const ctx = await fixture('../internal/pqcrypto/testdata/vectors/context.json');
  call('sync', { trust: {
    fingerprint: ctx.fingerprint, bundle: encode(ctx.bundle), manifests: ctx.manifests.map(encode),
  } });
  const identity = { issuer: 'https://idp.example.test', subject: 'test-subject', method: 'passphrase' };
  const input = { ...identity, passphrase: 'browser vault test passphrase' };
  const bundle = call('new-key', input);
  assert.throws(() => call('unlock', { ...input, ...bundle, passphrase: 'wrong passphrase' }), /could not be unlocked/);
  call('unlock', { ...input, ...bundle });
  call('lock');
});
