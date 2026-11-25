import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BreakGlassBanner } from './BreakGlassBanner';

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it('asks a break-glass session for its reason, then shows it', async () => {
  const fetcher = vi.fn(async () => new Response('{"recorded":true}', { status: 200 }));
  vi.stubGlobal('fetch', fetcher);
  const onReason = vi.fn();
  render(<BreakGlassBanner state={{ reason: '', expires_at: '2026-11-25T12:00:00Z' }} onReason={onReason} />);
  expect(screen.getByRole('region', { name: 'Break-glass session' })).toBeTruthy();
  fireEvent.change(screen.getByLabelText('Reason for this session'), { target: { value: 'IdP outage' } });
  fireEvent.click(screen.getByRole('button', { name: 'Record reason' }));
  await waitFor(() => expect(onReason).toHaveBeenCalledWith('IdP outage'));
  expect(fetcher).toHaveBeenCalledWith('/api/auth/break-glass/reason', expect.objectContaining({ method: 'POST', body: JSON.stringify({ reason: 'IdP outage' }) }));
});

it('keeps the banner once the reason is given', () => {
  render(<BreakGlassBanner state={{ reason: 'IdP outage', expires_at: '2026-11-25T12:00:00Z' }} onReason={vi.fn()} />);
  expect(screen.getByRole('region', { name: 'Break-glass session' }).textContent).toContain('Reason: IdP outage');
  expect(screen.queryByRole('button', { name: 'Record reason' })).toBeNull();
});
