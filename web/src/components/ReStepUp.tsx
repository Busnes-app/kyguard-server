import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { onStepupStale, secureFetch } from '../api';

// ReStepUp asks for a fresh authenticator code when a privileged action's step-up window has
// passed (403 stepup_stale), so the action can go through without signing in again.
export function ReStepUp() {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // Every action waiting on this prompt: concurrent refusals share one dialog and all of them
  // hear its answer.
  const waiting = useRef<((ok: boolean) => void)[]>([]);

  const finish = (ok: boolean) => {
    const resolvers = waiting.current;
    waiting.current = [];
    setOpen(false);
    resolvers.forEach((resolve) => resolve(ok));
  };

  useEffect(() => {
    onStepupStale(() => new Promise<boolean>((resolve) => {
      if (waiting.current.length === 0) {
        setCode('');
        setError('');
        setOpen(true);
      }
      waiting.current.push(resolve);
    }));
    // Leaving the shell (signing out) cancels an open prompt: its callers get the refusal.
    return () => {
      onStepupStale(null);
      waiting.current.splice(0).forEach((resolve) => resolve(false));
    };
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const response = await secureFetch('/api/auth/stepup/totp', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }),
      });
      if (response.ok) { finish(true); return; }
      const body: unknown = await response.json().catch(() => ({}));
      setError(typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string' ? body.error : 'The code was not accepted.');
      setCode('');
    } finally { setBusy(false); }
  }

  if (!open) return null;
  return (
    <div role="dialog" aria-modal="true" aria-labelledby="restepup-title" className="modal-backdrop"
      style={{ position: 'fixed', inset: 0, display: 'grid', placeItems: 'center', background: 'rgba(0,0,0,0.5)', zIndex: 1000 }}>
      <form className="panel" onSubmit={submit} style={{ width: '100%', maxWidth: 400 }}>
        <h2 id="restepup-title">Confirm it is you</h2>
        <p>This action needs a fresh authenticator code.</p>
        <label htmlFor="restepup-code">Authenticator code</label>
        <input id="restepup-code" type="text" inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9]{6}" maxLength={6} autoFocus
          value={code} onChange={(event) => setCode(event.target.value.trim())} />
        {error && <p role="alert">{error}</p>}
        <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
          <button type="submit" disabled={busy}>Confirm</button>
          <button type="button" className="btn-secondary" disabled={busy} onClick={() => finish(false)}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
