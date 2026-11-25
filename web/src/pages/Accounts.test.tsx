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
