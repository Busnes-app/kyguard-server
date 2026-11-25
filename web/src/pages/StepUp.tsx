import { useEffect, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import { secureFetch } from '../api';

export interface StepUpState {
  required: boolean;
  enrolled: boolean;
  can_enroll: boolean;
}

interface Props {
  state: StepUpState;
  // Loads the active session; rejects when it could not, so the user can retry the load.
  onDone: () => Promise<void>;
  onLogout: () => void;
}

async function errorOf(response: Response, fallback: string): Promise<string> {
  const body: unknown = await response.json().catch(() => ({}));
  return typeof body === 'object' && body !== null && 'error' in body && typeof body.error === 'string' ? body.error : fallback;
}

// Every SSO sign-in ends here (spec §7.3): a TOTP code turns the pending session into an
// active one. A first factor can be enrolled only when the identity provider asserted MFA.
export function StepUp({ state, onDone, onLogout }: Props) {
  const [code, setCode] = useState('');
  const [offer, setOffer] = useState<{ secret: string; otpauth_uri: string } | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // The code was accepted: the session is active, so only the load is retried, never the code.
  const [exchanged, setExchanged] = useState(false);

  async function finish() {
    setBusy(true);
    setError('');
    try { await onDone(); } catch {
      setError('You are signed in, but KyGuard could not load your session. Try again.');
    } finally { setBusy(false); }
  }

  async function startEnrollment() {
    setBusy(true);
    setError('');
    try {
      const response = await secureFetch('/api/auth/stepup/enroll', { method: 'POST' });
      if (!response.ok) throw new Error(await errorOf(response, 'Enrollment failed.'));
      setOffer(await response.json());
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Enrollment failed.');
    } finally { setBusy(false); }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const path = offer ? '/api/auth/stepup/enroll/confirm' : '/api/auth/stepup/totp';
      const response = await secureFetch(path, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code }),
      });
      if (!response.ok) throw new Error(await errorOf(response, 'The code was not accepted.'));
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The code was not accepted.');
      setCode('');
      setBusy(false);
      return;
    }
    setExchanged(true);
    await finish();
  }

  const blocked = !state.enrolled && !state.can_enroll;
  // A blocked user is refused by the enroll route, which records auth.enrollment_blocked for
  // the administrators (spec §7.3 rule 3); the screen says they were told only after that 403.
  const [notified, setNotified] = useState<boolean | null>(null);
  const asked = useRef(false);
  useEffect(() => {
    if (!blocked || asked.current) return;
    asked.current = true;
    secureFetch('/api/auth/stepup/enroll', { method: 'POST' })
      .then((response) => setNotified(response.status === 403))
      .catch(() => setNotified(false));
  }, [blocked]);
  return (
    <main style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 20 }}>
      <div className="panel" style={{ width: '100%', maxWidth: 440 }}>
        <h1>Confirm it is you</h1>
        {blocked && notified !== null && <p role="alert">Your identity provider did not confirm a multi-factor sign-in, so an authenticator cannot be set up here. {notified ? 'An administrator has been notified.' : 'Sign out and sign in again, or contact an administrator.'}</p>}
        {!exchanged && !state.enrolled && state.can_enroll && !offer && (
          <>
            <p>Set up an authenticator app for KyGuard. You will enter one of its codes after every sign-in.</p>
            <button type="button" disabled={busy} onClick={startEnrollment}>Set up authenticator</button>
          </>
        )}
        {!exchanged && offer && (
          <>
            <p>Add this account to your authenticator app, then enter the code it shows.</p>
            <p><label htmlFor="totp-secret">Secret</label></p>
            <input id="totp-secret" readOnly value={offer.secret} />
            <p style={{ wordBreak: 'break-all', fontSize: 12 }}>{offer.otpauth_uri}</p>
          </>
        )}
        {exchanged && <button type="button" disabled={busy} onClick={finish}>Try again</button>}
        {!exchanged && (state.enrolled || offer) && (
          <form onSubmit={submit}>
            <label htmlFor="stepup-code">Authenticator code</label>
            <input id="stepup-code" type="text" inputMode="numeric" autoComplete="one-time-code" required pattern="[0-9]{6}" maxLength={6}
              value={code} onChange={(event) => setCode(event.target.value.trim())} />
            <button type="submit" disabled={busy} style={{ marginTop: 12 }}>Continue</button>
          </form>
        )}
        {error && <p role="alert">{error}</p>}
        <button type="button" className="btn-secondary" style={{ marginTop: 16 }} onClick={onLogout}>Sign out</button>
      </div>
    </main>
  );
}
