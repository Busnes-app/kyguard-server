import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ReStepUp } from './ReStepUp';
import { secureFetch } from '../api';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

const stale = () => new Response(JSON.stringify({ error: 'Confirm with your authenticator code first', code: 'stepup_stale' }), { status: 403 });

function stubServer() {
  let fresh = false;
  const fetcher = vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === '/api/auth/stepup/totp') { fresh = true; return new Response('{"stepped_up":true}', { status: 200 }); }
    return fresh ? new Response('{"ok":true}', { status: 200 }) : stale();
  });
  vi.stubGlobal('fetch', fetcher);
  return fetcher;
}

const calls = (fetcher: ReturnType<typeof vi.fn>, path: string) => fetcher.mock.calls.filter(([input]) => String(input) === path).length;

// §7.3 rule 6: an action refused for a stale step-up asks for a code and then goes through.
it('asks for a fresh code on stepup_stale and sends the action again', async () => {
  const fetcher = stubServer();
  render(<ReStepUp />);
  const action = secureFetch('/api/backup/deposit', { method: 'POST' });
  fireEvent.change(await screen.findByLabelText('Authenticator code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  expect((await action).status).toBe(200);
  expect(calls(fetcher, '/api/backup/deposit')).toBe(2);
  expect(fetcher).toHaveBeenCalledWith('/api/auth/stepup/totp', expect.objectContaining({ body: JSON.stringify({ code: '123456' }) }));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
});

it('returns the refusal when the user cancels, without sending the action again', async () => {
  const fetcher = stubServer();
  render(<ReStepUp />);
  const action = secureFetch('/api/backup/deposit', { method: 'POST' });
  fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
  expect((await action).status).toBe(403);
  expect(calls(fetcher, '/api/backup/deposit')).toBe(1);
});

it('does not prompt for any other 403', async () => {
  const fetcher = vi.fn(async () => new Response('{"error":"Forbidden"}', { status: 403 }));
  vi.stubGlobal('fetch', fetcher);
  render(<ReStepUp />);
  expect((await secureFetch('/api/backup/deposit', { method: 'POST' })).status).toBe(403);
  expect(screen.queryByRole('dialog')).toBeNull();
  expect(fetcher).toHaveBeenCalledOnce();
});

it('answers every action refused while the prompt was open', async () => {
  const fetcher = stubServer();
  render(<ReStepUp />);
  const first = secureFetch('/api/backup/deposit', { method: 'POST' });
  const second = secureFetch('/api/backup/deposit', { method: 'POST' });
  fireEvent.change(await screen.findByLabelText('Authenticator code'), { target: { value: '123456' } });
  expect(screen.getAllByRole('dialog')).toHaveLength(1);
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  expect((await first).status).toBe(200);
  expect((await second).status).toBe(200);
  expect(calls(fetcher, '/api/auth/stepup/totp')).toBe(1);
});

it('returns the refusal when the shell goes away with the prompt open', async () => {
  stubServer();
  const { unmount } = render(<ReStepUp />);
  const action = secureFetch('/api/backup/deposit', { method: 'POST' });
  await screen.findByRole('dialog');
  unmount();
  expect((await action).status).toBe(403);
});

it('shows a retryable error when the server cannot be reached', async () => {
  let reachable = false;
  vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
    if (String(input) === '/api/auth/stepup/totp') {
      if (!reachable) throw new TypeError('Failed to fetch');
      return new Response('{"stepped_up":true}', { status: 200 });
    }
    return reachable ? new Response('{}', { status: 200 }) : stale();
  }));
  render(<ReStepUp />);
  const action = secureFetch('/api/backup/deposit', { method: 'POST' });
  fireEvent.change(await screen.findByLabelText('Authenticator code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  expect((await screen.findByRole('alert')).textContent).toContain('Could not reach the server');
  reachable = true;
  fireEvent.change(screen.getByLabelText('Authenticator code'), { target: { value: '123456' } });
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  expect((await action).status).toBe(200);
});

it('keeps the shell inert while open and gives focus back on close', async () => {
  stubServer();
  render(<div><button type="button">Back up now</button><ReStepUp /></div>);
  const origin = screen.getByRole('button', { name: 'Back up now' });
  origin.focus();
  const action = secureFetch('/api/backup/deposit', { method: 'POST' });
  await screen.findByRole('dialog');
  expect(origin.inert).toBe(true);
  fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
  await action;
  await waitFor(() => expect(document.activeElement).toBe(origin));
  expect(origin.inert).toBe(false);
});
