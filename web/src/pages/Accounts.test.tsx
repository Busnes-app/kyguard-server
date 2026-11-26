import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Accounts } from './Accounts';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status });

const row = (id: string, cls: string, dept: string) => ({
  account_id: id, asset: 'dc1', name: 'svc-' + id, account_kind: 'managed', pool_id: 'p1', class: cls, health: 'healthy', health_reason: '',
  owner_user_id: 'u1', owner: 'alice', min_password_age_seconds: null, target_descriptor_digest: '', last_release: null,
  attributes: {}, owner_attributes: { department: dept },
});

const card = (rows: unknown[]) => ({
  generated_at: '2026-11-25T00:00:00Z',
  totals: { active: rows.length, decommissioned: 0, classes: { green: 1, yellow: 0, red: 1 }, percent: { green: 50, yellow: 0, red: 50 }, health: { healthy: 2 } },
  account_attribute_keys: [], owner_attribute_keys: ['department'], rows,
});

// Spec §8.3: one filter drives the table, the traffic light and both exports.
it('filters by owner department and exports exactly that filter', async () => {
  const urls: string[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    urls.push(url);
    if (url === '/api/attributes') return json({ account: [], user: [{ id: 'd1', entity: 'user', key: 'department', label: 'Department', type: 'string', enum_values: [], source: 'scim' }] });
    if (url.startsWith('/api/reports/scorecard')) {
      const all = [row('a', 'green', 'Ops'), row('b', 'red', 'Sales')];
      return json(card(url.includes('department=Ops') ? all.slice(0, 1) : all));
    }
    throw new Error(`unexpected fetch ${url}`);
  }));
  render(<Accounts isAdmin={false} />);
  expect(await screen.findByText('dc1 / svc-b')).toBeTruthy();
  expect(screen.getAllByText('Managed').length).toBeGreaterThan(0);

  fireEvent.change(screen.getByLabelText('Owner department'), { target: { value: 'Ops' } });
  await screen.findByText('Clear');
  await vi.waitFor(() => expect(screen.queryByText('dc1 / svc-b')).toBeNull());
  const csv = screen.getByText('Export CSV').closest('a')!;
  const exported = screen.getByText('Export JSON').closest('a')!;
  expect(csv.getAttribute('href')).toBe('/api/reports/scorecard?owner.department=Ops&format=csv');
  expect(exported.getAttribute('href')).toBe('/api/reports/scorecard?owner.department=Ops&format=json');
  // A user gets no inventory controls and never calls an admin route.
  expect(screen.queryByText('Add account')).toBeNull();
  expect(urls.some((u) => u.startsWith('/api/assets') || u.startsWith('/api/admin'))).toBe(false);
});

it('shows a refused scorecard instead of an empty inventory', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => json({ error: 'Authentication required' }, 401)));
  render(<Accounts isAdmin={false} />);
  expect((await screen.findAllByRole('alert'))[0].textContent).toMatch(/Authentication required/);
  expect(screen.queryByText('No accounts yet.')).toBeNull();
});

// A failed filtered load must not leave the previous rows on screen under the new filter.
it('drops the previous rows when a filtered load fails', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/api/attributes') return json({ account: [], user: [] });
    if (url.includes('class=red')) return json({ error: 'database unavailable' }, 500);
    return json(card([row('a', 'green', 'Ops'), row('b', 'red', 'Sales')]));
  }));
  render(<Accounts isAdmin={false} />);
  expect(await screen.findByText('dc1 / svc-b')).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Class'), { target: { value: 'red' } });
  expect((await screen.findByRole('alert')).textContent).toMatch(/database unavailable/);
  expect(screen.queryByText('dc1 / svc-a')).toBeNull();
});

it('defaults the first rotation to local time', async () => {
  const { localInput } = await import('../reporting');
  const d = new Date(2026, 10, 25, 9, 5);
  expect(localInput(d)).toBe('2026-11-25T09:05');
});

it('reports a write that never reached the server', async () => {
  const { send } = await import('../reporting');
  vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('Failed to fetch'); }));
  expect(await send('PATCH', '/api/accounts/x', { status: 'active' })).toMatch(/Could not reach the server/);
});

// Decommissioned accounts leave the traffic light; admins can still reach and reactivate them.
it('lets an admin reach decommissioned accounts', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url === '/api/attributes') return json({ account: [], user: [] });
    if (url === '/api/assets') return json([]);
    if (url === '/api/accounts?status=decommissioned') return json([{ ID: 'old', Name: 'old-sa', asset_name: 'db1' }]);
    if (url.startsWith('/api/reports/scorecard')) {
      const c = { ...card([row('a', 'green', 'Ops')]), account_attribute_keys: null, owner_attribute_keys: null };
      c.totals.decommissioned = 1;
      return json(c);
    }
    throw new Error(`unexpected fetch ${url}`);
  }));
  render(<Accounts isAdmin />);
  fireEvent.click(await screen.findByText('Show decommissioned accounts'));
  expect(await screen.findByText('db1 / old-sa')).toBeTruthy();
});

// A second Add while the first is still pending creates nothing more (one asset, one account).
it('creates one asset and one account when Add is clicked twice', async () => {
  const posts: string[] = [];
  let release: () => void = () => {};
  const held = new Promise<void>((r) => { release = r; });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'POST') {
      posts.push(url);
      await held;
      return json(url === '/api/assets' ? { ID: 'as1', Name: 'db1' } : { ID: 'ac1' }, 201);
    }
    if (url === '/api/attributes') return json({ account: [], user: [] });
    if (url === '/api/assets') return json([]);
    if (url.startsWith('/api/reports/scorecard')) return json(card([]));
    throw new Error(`unexpected fetch ${url}`);
  }));
  render(<Accounts isAdmin />);
  fireEvent.click(await screen.findByText('Add account'));
  fireEvent.change(screen.getByLabelText('New asset name'), { target: { value: 'db1' } });
  fireEvent.change(screen.getByLabelText('Account name'), { target: { value: 'svc' } });
  const form = screen.getByRole('form', { name: 'Add account' });
  fireEvent.submit(form);
  fireEvent.submit(form);
  release();
  await vi.waitFor(() => expect(posts).toContain('/api/accounts'));
  await new Promise((r) => setTimeout(r, 20));
  expect(posts.filter((u) => u === '/api/assets')).toHaveLength(1);
  expect(posts.filter((u) => u === '/api/accounts')).toHaveLength(1);
});

// A refused attribute save does not stay on screen as if it were stored, even after another
// edit succeeds and the detail reloads.
it('puts the stored attribute value back after a refused save', async () => {
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'PUT') return json({ error: 'refused' }, 409);
    if (init?.method === 'PATCH') return json({});
    if (url === '/api/attributes') return json({ account: [{ id: 'cc', entity: 'account', key: 'cost_center', label: 'Cost center', type: 'string', enum_values: [], source: 'admin' }], user: [] });
    if (url === '/api/accounts/a') return json({ account: { ID: 'a', Name: 'svc-a', AccountKind: 'managed', Status: 'active', asset_name: 'dc1', owner_user_id: 'u1', min_password_age_seconds: null }, descriptors: [], attributes: { cost_center: 'CC1' } });
    if (url.startsWith('/api/reports/scorecard')) return json(card([row('a', 'green', 'Ops')]));
    throw new Error(`unexpected fetch ${url}`);
  }));
  render(<Accounts isAdmin />);
  fireEvent.click(await screen.findByText('dc1 / svc-a'));
  const field = (await screen.findByLabelText('Cost center')) as HTMLInputElement;
  fireEvent.change(field, { target: { value: 'CC2' } });
  fireEvent.blur(field);
  expect(await screen.findByText('refused')).toBeTruthy();
  fireEvent.click(screen.getByText('Clear')); // a successful owner change reloads the detail
  await vi.waitFor(() => expect(screen.queryByText('refused')).toBeNull());
  expect((screen.getByLabelText('Cost center') as HTMLInputElement).value).toBe('CC1');
});

it('preserves a new edit and focus when the previous save reloads account details', async () => {
  const saves = vi.fn();
  let release: () => void = () => {};
  const held = new Promise<void>((resolve) => { release = resolve; });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'PUT') { saves(init.body); return json({}); }
    if (url === '/api/attributes') return json({ account: [{ id: 'cc', entity: 'account', key: 'cost_center', label: 'Cost center', type: 'string', enum_values: [], source: 'admin' }], user: [] });
    if (url === '/api/accounts/a') {
      const saved = saves.mock.calls.length;
      if (saved > 0) await held;
      return json({ account: { ID: 'a', Name: 'svc-a', AccountKind: 'managed', Status: 'active', asset_name: 'dc1', owner_user_id: '', min_password_age_seconds: saved ? 60 : null }, descriptors: [], attributes: { cost_center: ['CC1', 'CC2', 'CC3'][saved] } });
    }
    if (url.startsWith('/api/reports/scorecard')) return json(card([row('a', 'green', 'Ops')]));
    throw new Error('unexpected fetch ' + url);
  }));
  render(<Accounts isAdmin />);
  fireEvent.click(await screen.findByText('dc1 / svc-a'));
  const field = await screen.findByLabelText('Cost center');
  if (!(field instanceof HTMLInputElement)) throw new Error('Expected a text input');
  screen.getByLabelText('Account details').setAttribute('open', ''); // jsdom does not open the native modal.
  fireEvent.change(field, { target: { value: 'CC2' } });
  fireEvent.blur(field);
  const readOnlyDuringSave = field.readOnly;
  await vi.waitFor(() => expect(field.readOnly).toBe(false));

  field.focus();
  fireEvent.change(field, { target: { value: 'CC3' } });
  release();
  await screen.findByText('Minimum password age: 60 s');
  expect(screen.getByLabelText('Cost center') === field).toBe(true);
  expect(document.activeElement === field).toBe(true);
  expect(field.value).toBe('CC3');
  expect(readOnlyDuringSave).toBe(true);

  fireEvent.blur(field);
  await vi.waitFor(() => expect(saves).toHaveBeenLastCalledWith(JSON.stringify({ value: 'CC3' })));
});

// Closing the detail while a save is in flight reloads the page only after the save lands,
// so the table never keeps the value from before it.
it.each(['Close', 'Escape'])('waits for a save before closing with %s and reloading accounts', async (closeWith) => {
  const log: string[] = [];
  let release: () => void = () => {};
  const held = new Promise<void>((r) => { release = r; });
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'PUT') { await held; log.push('saved'); return json({}); }
    if (url === '/api/attributes') return json({ account: [{ id: 'cc', entity: 'account', key: 'cost_center', label: 'Cost center', type: 'string', enum_values: [], source: 'admin' }], user: [] });
    if (url === '/api/accounts/a') return json({ account: { ID: 'a', Name: 'svc-a', AccountKind: 'managed', Status: 'active', asset_name: 'dc1', owner_user_id: '', min_password_age_seconds: null }, descriptors: [], attributes: { cost_center: 'CC1' } });
    if (url.startsWith('/api/reports/scorecard')) { log.push('scorecard'); return json(card([row('a', 'green', 'Ops')])); }
    throw new Error(`unexpected fetch ${url}`);
  }));
  render(<Accounts isAdmin />);
  fireEvent.click(await screen.findByText('dc1 / svc-a'));
  const field = (await screen.findByLabelText('Cost center')) as HTMLInputElement;
  fireEvent.change(field, { target: { value: 'CC2' } });
  if (closeWith === 'Escape') {
    const dialog = screen.getByLabelText('Account details');
    dialog.setAttribute('open', ''); // jsdom does not open the native modal.
    field.focus();
    expect(document.activeElement === field).toBe(true);
    expect(fireEvent(dialog, new Event('cancel', { cancelable: true }))).toBe(false);
  } else {
    fireEvent.blur(field);
    fireEvent.click(screen.getByLabelText('Close'));
  }
  expect(field.closest('[inert]')).not.toBeNull();
  expect(screen.getByLabelText('Account details')).toBeTruthy();
  release();
  await vi.waitFor(() => expect(screen.queryByLabelText('Account details')).toBeNull());
  await vi.waitFor(() => {
    expect(log).toContain('saved');
    expect(log.lastIndexOf('scorecard')).toBeGreaterThan(log.indexOf('saved'));
  });
});

// A save that was pending at close and then refused keeps the dialog open with its error.
it('keeps account details open when a save pending at close is refused', async () => {
  let release: () => void = () => {};
  const held = new Promise<void>((r) => { release = r; });
  const onPage = vi.fn();
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === 'PUT') { await held; return json({ error: 'refused' }, 409); }
    if (url === '/api/attributes') return json({ account: [{ id: 'cc', entity: 'account', key: 'cost_center', label: 'Cost center', type: 'string', enum_values: [], source: 'admin' }], user: [] });
    if (url === '/api/accounts/a') return json({ account: { ID: 'a', Name: 'svc-a', AccountKind: 'managed', Status: 'active', asset_name: 'dc1', owner_user_id: '', min_password_age_seconds: null }, descriptors: [], attributes: { cost_center: 'CC1' } });
    if (url.startsWith('/api/reports/scorecard')) { onPage(); return json(card([row('a', 'green', 'Ops')])); }
    throw new Error(`unexpected fetch ${url}`);
  }));
  render(<Accounts isAdmin />);
  fireEvent.click(await screen.findByText('dc1 / svc-a'));
  const field = (await screen.findByLabelText('Cost center')) as HTMLInputElement;
  fireEvent.change(field, { target: { value: 'CC2' } });
  fireEvent.blur(field);
  fireEvent.click(screen.getByLabelText('Close'));
  const before = onPage.mock.calls.length;
  release();
  expect(await screen.findByText('refused')).toBeTruthy();
  await new Promise((r) => setTimeout(r, 20));
  expect(screen.getByLabelText('Account details')).toBeTruthy();
  expect(field.closest('[inert]')).toBeNull();
  expect(onPage.mock.calls.length).toBe(before);
});
