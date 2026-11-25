import { useState } from 'react';
import type { FormEvent } from 'react';
import { secureFetch } from '../api';

export interface BreakGlassState {
  reason: string;
  expires_at: string;
}

interface Props {
  state: BreakGlassState;
  onReason: (reason: string) => void;
}

// Shown on every page of a break-glass session (spec §7.4). Until the session states its
// reason the server refuses every privileged action, so the banner asks for it first.
export function BreakGlassBanner({ state, onReason }: Props) {
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const ends = new Date(state.expires_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const response = await secureFetch('/api/auth/break-glass/reason', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reason }),
      });
      const body: unknown = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string' ? body.error : 'The reason was not recorded.');
      }
      onReason(reason.trim());
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The reason was not recorded.');
    } finally { setBusy(false); }
  }

  return (
    <div role="region" aria-label="Break-glass session" className="break-glass-banner">
      <strong>Break-glass session</strong>
      <span> · ends at {ends}, no extension · every action is audited.</span>
      {state.reason
        ? <span> Reason: {state.reason}</span>
        : (
          <form onSubmit={submit} style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
            <label htmlFor="break-glass-reason">Reason for this session</label>
            <input id="break-glass-reason" required maxLength={500} value={reason} onChange={(event) => setReason(event.target.value)} style={{ flex: '1 1 16rem' }} />
            <button type="submit" disabled={busy}>Record reason</button>
            {error && <p role="alert">{error}</p>}
          </form>
        )}
    </div>
  );
}
