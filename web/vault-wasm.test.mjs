import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import { runInNewContext } from 'node:vm';

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

test('the compiled vault worker ignores messages outside its native channel', async () => {
  const name = (await readdir(assets)).find((file) => /^vaultWorker-.*\.js$/.test(file));
  assert.ok(name, 'the vault build includes the worker');
  const self = { postMessage: () => assert.fail('An untrusted message reached the vault runtime') };
  runInNewContext(await readFile(new URL(name, assets), 'utf8'), { self });

  const data = { id: 1, input: { action: 'lock' } };
  await self.onmessage({ isTrusted: false, origin: '', data });
  await self.onmessage({ isTrusted: true, origin: 'https://other.example', data });
});

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
  assert.throws(() => call('unlock', { ...identity, ...bundle }), /sign in with the KyIdentity keyring/);
  call('keyring-open', { user_id: identity.user_id, seed: vector.seed, handoff: vector.handoff });
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

test('the browser applies shared pool history across separate account views', async () => {
  const ctx = await fixture('../internal/pqcrypto/testdata/vectors/context.json');
  const common = ctx.manifests.filter(m => m.type === 'key_enrollment' || m.type === 'pool');
  const [accountA, accountB] = ctx.manifests.filter(m => m.type === 'policy' && m.account_kind === 'managed');
  const newer = { fingerprint: ctx.fingerprint, bundle: encode(ctx.bundle), manifests: [...common, accountA].map(encode) };
  const older = { ...newer, manifests: [...common.filter(m => m.type !== 'pool' || m.epoch === '1'), accountB].map(encode) };
  const observed = call('sync', { trust: newer }).heads;
  const pool = 'pool/' + accountA.pool_id;
  assert.equal(observed[pool].epoch, '2');
  assert.throws(() => call('sync', { trust: { ...older, observed } }), /older or conflicting/);
  const current = call('sync', { trust: { ...newer, manifests: [...common, accountB].map(encode), observed } }).heads;
  assert.equal(current[pool].epoch, '2');
  assert.equal(current['policy/'+accountA.account_id], undefined);
  call('sync', { trust: older });
  assert.throws(() => call('reserve', { observed }), /older or conflicting/);
});

test('after Custodian rotation the browser accepts only known history from the retired quorum', async () => {
  const ctx = await fixture('../internal/pqcrypto/testdata/vectors/context.json');
  const [rotation] = await fixture('../internal/pqcrypto/testdata/vectors/custodian_set.json');
  const [pool] = await fixture('../internal/pqcrypto/testdata/vectors/pool.json');
  const [originalPool, retiredQuorumUpdate] = ctx.manifests.filter(m => m.type === 'pool');
  const trust = { fingerprint: ctx.fingerprint, bundle: encode(ctx.bundle) };
  const { heads: observed, verified } = call('sync', {
    trust: { ...trust, manifests: [originalPool, rotation.object].map(encode) },
  });
  const replay = (manifests) => call('sync', {
    trust: { ...trust, observed, verified, manifests: manifests.map(encode) },
  });

  assert.throws(() => replay([originalPool, retiredQuorumUpdate, rotation.object]), /retired Custodian/);
  const recovered = call('sync', {
    trust: { ...trust, observed, manifests: [originalPool, rotation.object].map(encode) },
  });
  assert.equal(recovered.heads['pool/' + originalPool.pool_id].epoch, '1');

  const current = replay([originalPool, rotation.object, pool.object]);
  assert.equal(current.heads['pool/' + originalPool.pool_id].epoch, '3');
});
