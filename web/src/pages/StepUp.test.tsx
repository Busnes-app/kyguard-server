import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { StepUp } from './StepUp';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('exchanges a pending session with a code', async () => {
  const fetcher = vi.fn(async () => new Response('{"authenticated":true}', { status: 200 }));
  vi.stubGlobal('fetch', fetcher);
  const done = vi.fn();
  render(<StepUp state={{ required: true, enrolled: true, can_enroll: false }} onDone={done} onLogout={vi.fn()} />);
  fireEvent.change(screen.getByLabelText('Authenticator code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  await waitFor(() => expect(done).toHaveBeenCalledOnce());
  expect(fetcher).toHaveBeenCalledWith('/api/auth/stepup/totp', expect.objectContaining({ body: JSON.stringify({ code: '123456' }) }));
});

it('enrolls a first factor, then confirms it', async () => {
  const fetcher = vi.fn(async (input: RequestInfo | URL) => new Response(String(input).endsWith('/enroll')
    ? JSON.stringify({ secret: 'ABCDEFGHIJKLMNOP', otpauth_uri: 'otpauth://totp/KyGuard:amy?secret=ABCDEFGHIJKLMNOP' })
    : '{"authenticated":true}', { status: 200 }));
  vi.stubGlobal('fetch', fetcher);
  const done = vi.fn();
  render(<StepUp state={{ required: true, enrolled: false, can_enroll: true }} onDone={done} onLogout={vi.fn()} />);
  fireEvent.click(screen.getByRole('button', { name: 'Set up authenticator' }));
  expect(((await screen.findByLabelText('Secret')) as HTMLInputElement).value).toBe('ABCDEFGHIJKLMNOP');
  fireEvent.change(screen.getByLabelText('Authenticator code'), { target: { value: '654321' } });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  await waitFor(() => expect(done).toHaveBeenCalledOnce());
  expect(fetcher).toHaveBeenLastCalledWith('/api/auth/stepup/enroll/confirm', expect.objectContaining({ body: JSON.stringify({ code: '654321' }) }));
});

it('reports a blocked enrollment to the server before saying admins were notified', async () => {
  const fetcher = vi.fn(async () => new Response('{"error":"blocked"}', { status: 403 }));
  vi.stubGlobal('fetch', fetcher);
  render(<StepUp state={{ required: true, enrolled: false, can_enroll: false }} onDone={vi.fn()} onLogout={vi.fn()} />);
  expect((await screen.findByRole('alert')).textContent).toContain('An administrator has been notified');
  expect(fetcher).toHaveBeenCalledWith('/api/auth/stepup/enroll', expect.objectContaining({ method: 'POST' }));
  expect(screen.queryByLabelText('Authenticator code')).toBeNull();
  expect(screen.getByRole('button', { name: 'Sign out' })).toBeTruthy();
});

it('does not claim a notification the server did not record', async () => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline'); }));
  render(<StepUp state={{ required: true, enrolled: false, can_enroll: false }} onDone={vi.fn()} onLogout={vi.fn()} />);
  const alert = await screen.findByRole('alert');
  expect(alert.textContent).toContain('did not confirm a multi-factor sign-in');
  expect(alert.textContent).not.toContain('notified');
});

it('retries only the session load after an accepted code', async () => {
  const fetcher = vi.fn(async () => new Response('{"authenticated":true}', { status: 200 }));
  vi.stubGlobal('fetch', fetcher);
  const done = vi.fn().mockRejectedValueOnce(new Error('offline')).mockResolvedValueOnce(undefined);
  render(<StepUp state={{ required: true, enrolled: true, can_enroll: false }} onDone={done} onLogout={vi.fn()} />);
  fireEvent.change(screen.getByLabelText('Authenticator code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
  expect((await screen.findByRole('alert')).textContent).toContain('could not load your session');
  expect(screen.queryByLabelText('Authenticator code')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
  await waitFor(() => expect(done).toHaveBeenCalledTimes(2));
  expect(fetcher).toHaveBeenCalledOnce();
});
