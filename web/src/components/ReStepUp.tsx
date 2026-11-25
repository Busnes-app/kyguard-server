import { useEffect, useLayoutEffect, useRef, useState } from 'react';
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
  const dialog = useRef<HTMLDivElement>(null);
  const returnTo = useRef<HTMLElement | null>(null);
  // The code check in flight: Cancel aborts it, so a stalled request never traps the user.
  const inFlight = useRef<AbortController | null>(null);

  // While open the shell behind is inert, so Tab and clicks stay in the dialog; on close focus
  // goes back to where it was. A layout effect: inert lands in the commit that shows the dialog.
  useLayoutEffect(() => {
    if (!open || !dialog.current) return;
    const behind = Array.from(dialog.current.parentElement?.children ?? []).filter((el): el is HTMLElement => el !== dialog.current && el instanceof HTMLElement && !el.inert);
    behind.forEach((el) => { el.inert = true; });
    return () => {
      behind.forEach((el) => { el.inert = false; });
      returnTo.current?.focus();
    };
  }, [open]);

  const finish = (ok: boolean) => {
    inFlight.current?.abort();
    inFlight.current = null;
    setBusy(false);
    const resolvers = waiting.current;
    waiting.current = [];
    setOpen(false);
    resolvers.forEach((resolve) => resolve(ok));
  };

  useEffect(() => {
    onStepupStale(() => new Promise<boolean>((resolve) => {
      if (waiting.current.length === 0) {
        returnTo.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
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
    const controller = new AbortController();
    inFlight.current = controller;
    // Only the current submission may change the dialog: a cancelled one can finish late,
    // after another prompt opened.
    const current = () => inFlight.current === controller;
    setBusy(true);
    setError('');
    try {
      const response = await secureFetch('/api/auth/stepup/totp', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }), signal: controller.signal,
      });
      if (!current()) return;
      if (response.ok) { finish(true); return; }
      const body: unknown = await response.json().catch(() => ({}));
      if (!current()) return;
      setError(typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string' ? body.error : 'The code was not accepted.');
      setCode('');
    } catch {
      if (current()) setError('Could not reach the server. Check the connection and try again.');
    } finally {
      if (current()) { inFlight.current = null; setBusy(false); }
    }
  }

  if (!open) return null;
  return (
    <div ref={dialog} role="dialog" aria-modal="true" aria-labelledby="restepup-title" className="modal-backdrop"
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
          <button type="button" className="btn-secondary" onClick={() => finish(false)}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
