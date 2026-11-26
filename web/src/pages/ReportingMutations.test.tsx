import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Accounts } from './Accounts';
import { Attributes } from './Attributes';
import { Policies } from './Policies';

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

it.each([200, 409])('blocks draft save and deletion until the first PUT returns HTTP %i', async (firstStatus) => {
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  const writes: string[] = [];
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/api/accounts/a/policy-draft' && init?.method === 'PUT') {
      writes.push(String(init.body));
      if (writes.length === 1) {
        await held;
        if (firstStatus === 409) return json({ error: 'Draft was refused' }, firstStatus);
      }
      return json({});
    }
    if (url === '/api/policy-drafts/d' && init?.method === 'DELETE') {
      writes.push('delete');
      return json({});
    }
    if (url === '/api/policy-drafts') {
      return json([{ id: 'd', account_id: 'a', account: 'svc-a', epoch: 1, digest: 'digest', signatures: 0, status: 'needs_signatures' }]);
    }
    if (url === '/api/reports/scorecard') return json({ rows: [{ account_id: 'a', asset: 'dc1', name: 'svc-a', account_kind: 'vaulted' }] });
    if (url === '/api/trust') return json({ imported: true });
    if (url === '/api/principals') return json([]);
    if (url === '/api/accounts/a') return json({ descriptors: [] });
    throw new Error('unexpected fetch ' + url);
  }));

  render(<Policies isAdmin />);
  await screen.findByRole('option', { name: 'dc1 / svc-a (vaulted)' });
  fireEvent.change(screen.getByLabelText('Account'), { target: { value: 'a' } });
  const form = screen.getByRole('form', { name: 'New policy draft' });
  const save = screen.getByRole('button', { name: 'Save draft' });
  const remove = await screen.findByRole('button', { name: 'Delete draft' });
  fireEvent.submit(form);
  fireEvent.change(screen.getByLabelText('Max checkout (s)'), { target: { value: '7200' } });
  fireEvent.submit(form); // bypass the disabled button to exercise the submit handler
  fireEvent.click(remove);
  const writesWhilePending = [...writes];
  const controlsWhilePending = [save, remove].map((control) => control.hasAttribute('disabled'));
  release();

  await screen.findByText(firstStatus === 200 ? 'Draft saved. Custodians can now sign it.' : 'Draft was refused');
  expect(writesWhilePending).toHaveLength(1);
  expect(writesWhilePending[0]).toContain('"max_checkout_ttl_seconds":3600');
  expect(controlsWhilePending).toEqual([true, true]);
  expect(save.hasAttribute('disabled')).toBe(false);

  fireEvent.submit(form);
  await vi.waitFor(() => expect(writes).toHaveLength(2));
  expect(writes[1]).toContain('"max_checkout_ttl_seconds":7200');
  await vi.waitFor(() => expect(save.hasAttribute('disabled')).toBe(false));
  await screen.findByText('Draft saved. Custodians can now sign it.');
});

it('blocks duplicate deletion and creation while an attribute deletion is pending', async () => {
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  const writes: string[] = [];
  let deleted = false;
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/api/attributes/d' && init?.method === 'DELETE') {
      writes.push('delete');
      await held;
      deleted = true;
      return json({});
    }
    if (url === '/api/attributes' && init?.method === 'POST') {
      writes.push('create');
      return json({});
    }
    if (url === '/api/attributes') {
      return json({ account: deleted ? [] : [{ id: 'd', key: 'team', label: 'Old team', type: 'string', source: 'admin' }], user: [] });
    }
    throw new Error('unexpected fetch ' + url);
  }));

  render(<Attributes isAdmin />);
  const remove = await screen.findByRole('button', { name: 'Delete Old team' });
  const add = screen.getByRole('button', { name: 'Add attribute' });
  const form = screen.getByRole('form', { name: 'New attribute' });
  fireEvent.change(screen.getByLabelText('Label'), { target: { value: 'New team' } });
  fireEvent.change(screen.getByLabelText('Key'), { target: { value: 'team' } });
  fireEvent.click(remove);
  fireEvent.click(remove);
  fireEvent.submit(form);
  const writesWhilePending = [...writes];
  const controlsWhilePending = [add, remove].map((control) => control.hasAttribute('disabled'));
  release();

  await vi.waitFor(() => expect(screen.queryByText('Old team')).toBeNull());
  expect(writesWhilePending).toEqual(['delete']);
  expect(controlsWhilePending).toEqual([true, true]);
  fireEvent.submit(form);
  await vi.waitFor(() => expect(writes).toEqual(['delete', 'create']));
  await vi.waitFor(() => expect(add.hasAttribute('disabled')).toBe(false));
});

it('loads account attribute editors after a pending definition deletion settles', async () => {
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  let deleted = false;
  const obsolete = { id: 'd', key: 'team', label: 'Old team', type: 'string', source: 'admin' };
  const retained = { id: 'r', key: 'office', label: 'Office', type: 'string', source: 'admin' };
  vi.spyOn(window, 'confirm').mockReturnValue(true);
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url === '/api/attributes/d' && init?.method === 'DELETE') {
      await held;
      deleted = true;
      return json({});
    }
    if (url === '/api/attributes') return json({ account: deleted ? [retained] : [obsolete, retained], user: [] });
    if (url === '/api/assets') return json([]);
    if (url === '/api/accounts/a') {
      return json({ account: { ID: 'a', Name: 'svc-a', Status: 'active', asset_name: 'dc1' }, descriptors: [], attributes: {} });
    }
    if (url.startsWith('/api/reports/scorecard')) {
      return json({
        rows: [{ account_id: 'a', asset: 'dc1', name: 'svc-a', account_kind: 'vaulted', class: 'red', attributes: {}, owner_attributes: {} }],
        totals: { active: 1, decommissioned: 0, classes: { green: 0, yellow: 0, red: 1 }, percent: { green: 0, yellow: 0, red: 100 } },
      });
    }
    throw new Error('unexpected fetch ' + url);
  }));

  try {
    const view = render(<Attributes isAdmin />);
    fireEvent.click(await screen.findByRole('button', { name: 'Delete Old team' }));
    view.rerender(<Accounts isAdmin />);
    fireEvent.click(await screen.findByText('dc1 / svc-a'));
    await screen.findByText('Updating attribute definitions…');
    expect(screen.queryByLabelText('Old team')).toBeNull();
    expect(screen.queryByLabelText('Office')).toBeNull();

    release();
    await screen.findByLabelText('Office');
    expect(screen.queryByLabelText('Old team')).toBeNull();
  } finally {
    release();
  }
});
