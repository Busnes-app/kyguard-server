import { secureFetch } from './api';

export type VaultConfig = {
  fingerprint: string;
  keyring?: { issuer: string; client_id: string; org_id: string };
};

export interface KeyEnvelope {
  version: number;
  method: 'passphrase' | 'kyidentity';
  keyring_version?: string;
  key_version?: number;
  salt?: string;
  nonce: string;
  ciphertext: string;
}

export interface KeyUpload {
  enrollment: string;
  sealed: KeyEnvelope;
}

export interface VaultKeyInfo extends Partial<KeyUpload> {
  issuer: string;
  subject: string;
  bundle: string;
  manifests: string[];
}

export interface AccountContext {
  manifests: string[];
  target: string;
  envelope?: string;
  receipts?: string[];
}

interface Watermark {
  digest: string;
  epoch: string;
}

export interface VaultContext {
  heads: Record<string, Watermark>;
  target?: { host: string; port: number; identity: string; connector: string; digest: string };
  ttl?: number;
  approvals?: number;
  can_enroll?: boolean;
  can_checkout?: boolean;
  can_approve?: boolean;
}

let worker: Worker | undefined;
let id = 0;
const pending = new Map<number, { done: (value: unknown) => void; fail: (reason: Error) => void }>();

export function resetVault() {
  worker?.terminate();
  worker = undefined;
  for (const request of pending.values()) request.fail(new Error('The vault was locked.'));
  pending.clear();
  keyringUser = undefined;
}

function vaultWorker<T>(action: string, args: object = {}): Promise<T> {
  if (!worker) {
    worker = new Worker(new URL('./vaultWorker.ts', import.meta.url));
    worker.onmessage = (event: MessageEvent<{ id: number; output: { error?: string; value: unknown } }>) => {
      const request = pending.get(event.data.id);
      if (!request) return;
      pending.delete(event.data.id);
      const { error, value } = event.data.output;
      if (error) request.fail(new Error(error));
      else request.done(value);
    };
    worker.onerror = resetVault;
  }
  return new Promise<T>((resolve, reject) => {
    // The internal worker uses the typed Go request for each action.
    const complete: typeof resolve = resolve;
    pending.set(++id, { done: (value) => complete(value as T), fail: reject });
    worker?.postMessage({ id, input: { action, ...args } });
  });
}

export function closeVaultKey() {
  if (worker) void vaultWorker('close-key').catch(() => {});
}

export async function lockVault() {
  try {
    if (worker) await vaultWorker('lock').catch(() => {});
  } finally {
    resetVault();
    sessionStorage.removeItem(pendingKey);
  }
}

export async function vaultRequest<T>(path: string, method = 'GET', body?: object): Promise<T> {
  const response = await secureFetch(path, {
    method, redirect: 'error', cache: 'no-store',
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (response.status === 204) return undefined as T;
  const json = await response.json();
  if (!response.ok) {
    throw new Error(typeof json.error === 'string' ? json.error : 'The vault request failed.');
  }
  return json;
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export async function loadVaultConfig(): Promise<VaultConfig | null> {
  const response = await fetch('/.well-known/kyguard-vault.json', { redirect: 'error', cache: 'no-store' });
  if (!response.ok) return null;
  const raw: unknown = await response.json().catch(() => null);
  if (!record(raw) || typeof raw.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(raw.fingerprint)) return null;
  if (!record(raw.keyring)) return { fingerprint: raw.fingerprint };
  const { issuer, client_id, org_id } = raw.keyring;
  if (typeof issuer !== 'string' || typeof client_id !== 'string' || typeof org_id !== 'string') {
    throw new Error('The trusted vault keyring configuration is incomplete.');
  }
  const url = new URL(issuer);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
      issuer.endsWith('/') || !client_id || !org_id) throw new Error('The trusted KyIdentity issuer is invalid.');
  return { fingerprint: raw.fingerprint, keyring: { issuer, client_id, org_id } };
}

const callbackPath = '/vault/keyring-callback';
const pendingKey = 'kyguard:keyring-login';
let keyringUser: string | undefined;
export const keyringAvailable = (user: string) => keyringUser === user;

interface SignIn {
  state: string;
  nonce: string;
  issuer: string;
  client_id: string;
  redirect_uri: string;
}

export async function startKeyring(config: VaultConfig): Promise<void> {
  if (!config.keyring) throw new Error('KyIdentity keyring sign-in is unavailable.');
  const pair = await vaultWorker<{ seed: string; keyring_pk: string }>('keyring-start');
  const start = await vaultRequest<SignIn & { authorization_url: string }>('/api/sso/kysignon/keyring/start', 'POST', { keyring_pk: pair.keyring_pk });
  const url = new URL(start.authorization_url);
  const redirect = location.origin + callbackPath;
  if (url.origin !== new URL(config.keyring.issuer).origin || start.issuer !== config.keyring.issuer ||
      start.client_id !== config.keyring.client_id || start.redirect_uri !== redirect ||
      !/^[0-9a-f]{32}$/.test(start.state) || !/^[0-9a-f]{32}$/.test(start.nonce) ||
      url.searchParams.get('state') !== start.state || url.searchParams.get('nonce') !== start.nonce ||
      url.searchParams.get('redirect_uri') !== redirect || url.searchParams.get('client_id') !== start.client_id ||
      url.searchParams.get('keyring_pk') !== pair.keyring_pk || url.searchParams.get('code_challenge_method') !== 'S256') {
    throw new Error('KyIdentity sign-in did not match the trusted configuration.');
  }
  sessionStorage.setItem(pendingKey, JSON.stringify({ ...pair, state: start.state, nonce: start.nonce, expires: Date.now() + 300_000 }));
  location.assign(url);
}

export async function finishKeyring(): Promise<string> {
  if (location.pathname !== callbackPath) {
    const saved = sessionStorage.getItem(pendingKey);
    if (saved) {
      const pending: unknown = JSON.parse(saved);
      if (!record(pending) || typeof pending.expires !== 'number' || pending.expires <= Date.now()) sessionStorage.removeItem(pendingKey);
    }
    return '';
  }
  const query = new URLSearchParams(location.search);
  const fragment = new URLSearchParams(location.hash.slice(1));
  const saved = sessionStorage.getItem(pendingKey);
  sessionStorage.removeItem(pendingKey);
  history.replaceState(null, '', '/');
  if (!saved) throw new Error('The KyIdentity sign-in expired. Start again.');
  const pendingLogin: unknown = JSON.parse(saved);
  const code = query.get('code');
  if (!record(pendingLogin) || pendingLogin.state !== query.get('state') || typeof pendingLogin.state !== 'string' ||
      typeof pendingLogin.nonce !== 'string' || typeof pendingLogin.seed !== 'string' || typeof pendingLogin.keyring_pk !== 'string' ||
      typeof pendingLogin.expires !== 'number' || pendingLogin.expires <= Date.now() || !code ||
      query.getAll('code').length !== 1 || query.getAll('state').length !== 1) {
    throw new Error('The KyIdentity sign-in expired or changed. Start again.');
  }
  const config = await loadVaultConfig();
  if (!config?.keyring) throw new Error('The trusted KyIdentity keyring configuration is missing.');
  const binding = await vaultRequest<SignIn & { user_id: string; subject: string; org_id: string }>(
    '/api/sso/kysignon/keyring/exchange', 'POST', { code, state: pendingLogin.state });
  if (binding.issuer !== config.keyring.issuer || binding.client_id !== config.keyring.client_id ||
      binding.org_id !== config.keyring.org_id || binding.nonce !== pendingLogin.nonce ||
      typeof binding.user_id !== 'string' || !binding.user_id || typeof binding.subject !== 'string' || !binding.subject) {
    throw new Error('The KyIdentity account did not match this sign-in.');
  }
  if (!fragment.size) return 'Signed in without a suite key. A separate vault passphrase is available.';
  for (const name of ['kh', 'kh_pk', 'kh_kv', 'kh_rv']) {
    if (fragment.getAll(name).length !== 1) throw new Error('The KyIdentity keyring handoff was incomplete.');
  }
  const kv = fragment.get('kh_kv') ?? '';
  if (!/^[1-9][0-9]{0,9}$/.test(kv)) throw new Error('The KyIdentity key version is invalid.');
  await vaultWorker('keyring-open', { user_id: binding.user_id, seed: pendingLogin.seed, handoff: {
    issuer: binding.issuer, org_id: binding.org_id, subject: binding.subject, client_id: binding.client_id,
    nonce: pendingLogin.nonce, code, redirect_uri: location.origin + callbackPath, keyring_pk: pendingLogin.keyring_pk,
    keyring_version: fragment.get('kh_rv'), key_version: Number(kv), sender_key: fragment.get('kh_pk'), sealed: fragment.get('kh'),
  } });
  keyringUser = binding.user_id;
  return '';
}

function deploymentTrustKey(config: VaultConfig): string {
  return `kyguard:trust:${config.fingerprint}:deployment`;
}

function loadWatermarks(key: string): Record<string, unknown> {
  const saved: unknown = JSON.parse(localStorage.getItem(key) ?? '{}');
  if (!record(saved)) throw new Error('Browser trust state is invalid.');
  return saved;
}

function loadDeploymentTrust(key: string): { heads: Record<string, unknown>; verified: string[] } {
  const state = loadWatermarks(key);
  if (!('heads' in state)) return { heads: state, verified: [] };
  if (!record(state.heads) || !Array.isArray(state.verified) ||
      !state.verified.every((digest: unknown) => typeof digest === 'string' && /^[a-f0-9]{64}$/.test(digest))) {
    throw new Error('Browser trust state is invalid.');
  }
  return { heads: state.heads, verified: state.verified };
}

export function verifiedVaultWorker<T>(config: VaultConfig, action: string, args: object): Promise<T> {
  const key = deploymentTrustKey(config);
  return navigator.locks.request(key, () => vaultWorker<T>(action, { ...args, observed: loadDeploymentTrust(key).heads }));
}

export async function syncVault(config: VaultConfig, key: VaultKeyInfo, account?: string): Promise<VaultContext> {
  const ctx = account ? await vaultRequest<AccountContext>(`/api/accounts/${encodeURIComponent(account)}/vault-context`) : undefined;
  const viewKey = `kyguard:trust:${config.fingerprint}:${account ?? JSON.stringify([key.issuer, key.subject])}`;
  const globalKey = deploymentTrustKey(config);
  return navigator.locks.request(globalKey, async () => {
    const heads = loadWatermarks(viewKey);
    const { heads: observed, verified } = loadDeploymentTrust(globalKey);
    const result = await vaultWorker<VaultContext & { verified: string[] }>('sync', {
      trust: { fingerprint: config.fingerprint, bundle: key.bundle, manifests: ctx?.manifests ?? key.manifests, heads, observed, verified },
      context: ctx ? { ...ctx, account } : undefined,
    });
    localStorage.setItem(globalKey, JSON.stringify({
      heads: { ...observed, ...result.heads },
      verified: [...new Set([...verified, ...result.verified])],
    }));
    localStorage.setItem(viewKey, JSON.stringify(result.heads));
    return result;
  });
}

export function canonicalText(base64: string): string {
  return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(atob(base64.replaceAll('-', '+').replaceAll('_', '/')), (c) => c.charCodeAt(0)));
}

export function canonicalBytes(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let raw = '';
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
}
