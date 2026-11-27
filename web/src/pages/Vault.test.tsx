import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  canonicalBytes, syncVault, vaultRequest, verifiedVaultWorker,
  type KeyUpload, type VaultContext, type VaultKeyInfo,
} from '../vault';
import { Vault } from './Vault';

vi.mock('../vault', async (importOriginal) => ({
  ...await importOriginal<typeof import('../vault')>(),
  syncVault: vi.fn(),
  vaultRequest: vi.fn(),
  verifiedVaultWorker: vi.fn(),
}));

vi.mock('../reporting', () => ({
  useScorecard: () => ({ data: { rows: [] } }),
}));

const path = '/api/user/vault-key';
const config = { fingerprint: 'a'.repeat(64) };
const empty: VaultKeyInfo = {
  issuer: 'https://identity.example.test',
  subject: 'alice',
  bundle: 'bundle',
  manifests: [],
};
const upload: KeyUpload = {
  enrollment: canonicalBytes(JSON.stringify({
    principal_id: 'alice',
    keys: [{ sig_key_id: 'signing', enc_key_id: 'encryption' }],
  })),
  sealed: { version: 1, method: 'passphrase', nonce: 'nonce', ciphertext: 'ciphertext' },
};
const stored = { ...empty, ...upload };
const passphrase = 'test vault passphrase';
const request = vi.mocked(vaultRequest);
const sync = vi.mocked(syncVault);
const worker = vi.mocked(verifiedVaultWorker);

beforeEach(() => {
  vi.resetAllMocks();
  sync.mockResolvedValue({ heads: {} });
});

afterEach(cleanup);

it('unlocks with Custodian approval submitted after the page loaded', async () => {
  const approved = { ...stored, manifests: ['signed-enrollment'] };
  request.mockResolvedValueOnce(stored).mockResolvedValueOnce(approved);
  sync.mockImplementation(async (_config, info): Promise<VaultContext> => ({
    heads: info.manifests.length ? { 'key_enrollment/alice': { epoch: '1', digest: 'approved' } } : {},
  }));
  render(<Vault config={config} userID="alice" />);

  fireEvent.change(await screen.findByLabelText('Vault passphrase'), { target: { value: passphrase } });
  fireEvent.click(screen.getByRole('button', { name: 'Unlock vault' }));

  expect(await screen.findByRole('heading', { name: 'Managed credentials' })).toBeTruthy();
  expect(sync).toHaveBeenCalledWith(config, approved);
});

it('recovers a stored vault key after the upload response is lost', async () => {
  let saved: VaultKeyInfo = empty;
  request.mockImplementation(async (url, method) => {
    expect(url).toBe(path);
    if (method === 'PUT') {
      saved = stored;
      throw new TypeError('Network request failed after commit');
    }
    return saved;
  });
  worker.mockResolvedValueOnce(upload);
  render(<Vault config={config} userID="alice" />);

  fireEvent.change(await screen.findByLabelText('Vault passphrase'), { target: { value: passphrase } });
  fireEvent.change(screen.getByLabelText('Confirm passphrase'), { target: { value: passphrase } });
  fireEvent.click(screen.getByRole('button', { name: 'Create vault key' }));
  await screen.findByRole('button', { name: 'Unlock vault' });
  expect(screen.queryByRole('alert')).toBeNull();

  fireEvent.change(screen.getByLabelText('Vault passphrase'), { target: { value: passphrase } });
  fireEvent.click(screen.getByRole('button', { name: 'Unlock vault' }));
  expect(await screen.findByRole('button', { name: 'Download enrollment request' })).toBeTruthy();
  expect(worker.mock.calls.filter(([, action]) => action === 'new-key')).toHaveLength(1);
  expect(request.mock.calls.filter(([, method]) => method === 'PUT')).toHaveLength(1);
});
