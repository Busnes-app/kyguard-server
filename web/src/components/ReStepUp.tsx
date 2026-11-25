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
  const settle = useRef<((ok: boolean) => void) | null>(null);

  useEffect(() => {
    onStepupStale(() => new Promise<boolean>((resolve) => {
      settle.current = resolve;
      setCode('');
      setError('');
      setOpen(true);
    }));
    return () => onStepupStale(null);
  }, []);

  function finish(ok: boolean) {
    setOpen(false);
    settle.current?.(ok);
    settle.current = null;
  }

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
