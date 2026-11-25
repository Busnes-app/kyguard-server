import { useState } from 'react';
import type { FormEvent } from 'react';
import { secureFetch } from '../api';

export interface StepUpState {
  required: boolean;
  enrolled: boolean;
  can_enroll: boolean;
}

interface Props {
  state: StepUpState;
  onDone: () => void;
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
      onDone();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'The code was not accepted.');
      setCode('');
    } finally { setBusy(false); }
  }

  const blocked = !state.enrolled && !state.can_enroll;
  return (
    <main style={{ minHeight: '100vh', display: 'grid', placeItems: 'center', padding: 20 }}>
      <div className="panel" style={{ width: '100%', maxWidth: 440 }}>
        <h1>Confirm it is you</h1>
        {blocked && <p role="alert">Your identity provider did not confirm a multi-factor sign-in, so an authenticator cannot be set up here. An administrator has been notified.</p>}
        {!state.enrolled && state.can_enroll && !offer && (
          <>
            <p>Set up an authenticator app for KyGuard. You will enter one of its codes after every sign-in.</p>
            <button type="button" disabled={busy} onClick={startEnrollment}>Set up authenticator</button>
          </>
        )}
        {offer && (
          <>
            <p>Add this account to your authenticator app, then enter the code it shows.</p>
            <p><label htmlFor="totp-secret">Secret</label></p>
            <input id="totp-secret" readOnly value={offer.secret} />
            <p style={{ wordBreak: 'break-all', fontSize: 12 }}>{offer.otpauth_uri}</p>
          </>
        )}
        {(state.enrolled || offer) && (
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
