import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useScorecard } from '../reporting';
import {
  canonicalBytes, canonicalText, closeVaultKey, keyringAvailable, lockVault, startKeyring, syncVault, vaultRequest, verifiedVaultWorker,
  type KeyEnvelope, type KeyUpload, type VaultConfig, type VaultContext, type VaultKeyInfo,
} from '../vault';

interface Checkout {
  request_id: string;
  tx: string;
  stage: 'draft' | 'submitted' | 'checkin';
  approved: boolean;
}

interface ApprovalReview {
  requester: string;
  issuer: string;
  ttl: number;
  action: 'vault_checkout' | 'enroll';
}

interface Mailbox {
  challenge: string;
  purpose: string;
  delivery?: object;
  result: string;
  expires_at?: string;
  lease_state?: string;
}

const vaultKeyPath = '/api/user/vault-key';

function download(name: string, encoded: string) {
  const url = URL.createObjectURL(new Blob([canonicalText(encoded)], { type: 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function Vault({ config, userID }: { config: VaultConfig; userID: string }) {
  const scorecard = useScorecard();
  const [info, setInfo] = useState<VaultKeyInfo>();
  const [unlocked, setUnlocked] = useState(false);
  const [enrolledKey, setEnrolledKey] = useState<{ principal_id: string; sig_key_id: string; enc_key_id: string }>();
  const [approved, setApproved] = useState(false);
  const [passphrase, setPassphrase] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [account, setAccount] = useState('');
  const [context, setContext] = useState<VaultContext>();
  const [password, setPassword] = useState('');
  const [ttl, setTTL] = useState(300);
  const [approval, setApproval] = useState<{ tx: string; review: ApprovalReview }>();
  const [checkout, setCheckout] = useState<Checkout>();
  const [delivery, setDelivery] = useState<{ password: string; expires: number }>();
  const [reveal, setReveal] = useState(false);
  const [pendingEnrollment, setPendingEnrollment] = useState<{ request_id: string; tx: string; envelope: string }>();
  const [enrollment, setEnrollment] = useState<string>();
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const path = `/api/accounts/${encodeURIComponent(account)}`;
  const hasSuiteKey = keyringAvailable(userID);

  useEffect(() => closeVaultKey, []);

  useEffect(() => {
    let cancelled = false;
    void vaultRequest<VaultKeyInfo>(vaultKeyPath).then((data) => {
      if (!cancelled) setInfo(data);
    }).catch((err: Error) => {
      if (!cancelled) setError(err.message);
    });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (!delivery) return;
    const expires = window.setTimeout(() => {
      setDelivery(undefined);
      setReveal(false);
      setStatus('The lease expired. The broker will rotate the credential.');
    }, Math.max(0, delivery.expires - Date.now()));
    return () => window.clearTimeout(expires);
  }, [delivery]);

  async function run(operation: () => Promise<void>) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setError('');
    setStatus('');
    try {
      await operation();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'The vault action failed.');
    } finally {
      running.current = false;
      setBusy(false);
    }
  }

  async function keyAction(method: KeyEnvelope['method']) {
    if (!info) return;
    const secret = passphrase;
    setPassphrase('');
    setConfirmation('');
    const current = await vaultRequest<VaultKeyInfo>(vaultKeyPath);
    setInfo(current);
    if (current.sealed?.method !== info.sealed?.method) {
      setStatus(current.sealed ? 'Your key is stored. Unlock it to continue.' : 'Create a vault key to continue.');
      return;
    }
    const keyArgs = { user_id: userID, issuer: current.issuer, subject: current.subject, method, passphrase: secret };
    const trust = await syncVault(config, current);
    if (!current.sealed) {
      if (method === 'passphrase' && secret !== confirmation) throw new Error('The passphrases differ.');
      const upload = await verifiedVaultWorker<KeyUpload>(config, 'new-key', keyArgs);
      try {
        await vaultRequest(vaultKeyPath, 'PUT', upload);
        setInfo({ ...current, ...upload });
      } catch (error) {
        const saved = await vaultRequest<VaultKeyInfo>(vaultKeyPath).catch(() => undefined);
        if (!saved?.sealed || !saved.enrollment) throw error;
        setInfo(saved);
      }
      setStatus('Your key is stored. Unlock it to continue.');
      return;
    }
    if (!current.enrollment) throw new Error('Your signed enrollment is missing.');
    const draft: unknown = JSON.parse(canonicalText(current.enrollment));
    if (!draft || typeof draft !== 'object' || !('principal_id' in draft) || typeof draft.principal_id !== 'string') {
      throw new Error('Your signed enrollment is invalid.');
    }
    const key = 'keys' in draft && Array.isArray(draft.keys) ? draft.keys[0] : null;
    if (!key || typeof key.sig_key_id !== 'string' || typeof key.enc_key_id !== 'string') {
      throw new Error('Your enrollment fingerprints are missing.');
    }
    await verifiedVaultWorker(config, 'unlock', { ...keyArgs, sealed: current.sealed, enrollment: current.enrollment });
    setEnrolledKey({ principal_id: draft.principal_id, sig_key_id: key.sig_key_id, enc_key_id: key.enc_key_id });
    setUnlocked(true);
    setApproved(!!trust.heads[`key_enrollment/${draft.principal_id}`]);
  }

  async function selectAccount(id: string) {
    setAccount(id);
    setApproval(undefined);
    setContext(undefined);
    setEnrollment(undefined);
    setPassword('');
    if (!info || !id) return;
    const view = await syncVault(config, info, id);
    setContext(view);
    setTTL(Math.min(view.ttl || 1, 300));
  }

  async function refreshTarget() {
    if (!info || !context?.target) throw new Error('Select a verified account first.');
    const view = await syncVault(config, info, account);
    setContext(view);
    if (context.target.digest !== view.target?.digest) throw new Error('The target changed. Review it before trying again.');
    return view;
  }

  async function enrollAccount(e: FormEvent) {
    e.preventDefault();
    const credential = password;
    setPassword('');
    await run(async () => {
      const view = await refreshTarget();
      const reservation = await verifiedVaultWorker<{ request_id: string }>(config, 'reserve', {});
      const version = await vaultRequest<{ secret_version: string }>(`${path}/enrollments`, 'POST', reservation);
      const payload = await verifiedVaultWorker<{ tx: string; envelope: string }>(config, 'enroll', { reservation: reservation.request_id, version: version.secret_version, password: credential });
      if (view.approvals) {
        setPendingEnrollment({ request_id: reservation.request_id, ...payload });
        setStatus('Send the enrollment request file to an authorized approver.');
        return;
      }
      await submitEnrollment(reservation.request_id, payload);
    });
  }

  async function submitEnrollment(id: string, payload: { tx: string; envelope: string }) {
    await vaultRequest(`${path}/enrollments/${id}`, 'POST', payload);
    setPendingEnrollment(undefined);
    setEnrollment(id);
    setStatus('Enrollment sent to the broker.');
  }

  async function prepareCheckout(e: FormEvent) {
    e.preventDefault();
    await run(async () => {
      const view = await refreshTarget();
      const tx = await verifiedVaultWorker<Pick<Checkout, 'request_id' | 'tx'>>(config, 'checkout', { ttl });
      setCheckout({ ...tx, stage: 'draft', approved: view.approvals === 0 });
      if (view.approvals) setStatus('Send the request file to an authorized approver and load the approved copy.');
    });
  }

  async function submitCheckout() {
    if (!checkout) return;
    await vaultRequest(`${path}/transactions`, 'POST', { tx: checkout.tx });
    setCheckout({ ...checkout, stage: 'submitted' });
    setStatus('Checkout requested. Get the credential when the broker is ready.');
  }

  async function advanceCheckout() {
    if (!checkout) return;
    const txPath = `/api/transactions/${checkout.request_id}`;
    const mail = await vaultRequest<Mailbox>(txPath);
    if (mail.lease_state === 'rotation_pending' || mail.lease_state === 'closed') {
      setDelivery(undefined);
      setReveal(false);
      setCheckout(undefined);
      setStatus(mail.lease_state === 'closed' ? 'The checkout is closed.' : 'Checked in. The broker will rotate the credential.');
      return;
    }
    if (mail.result && mail.result !== 'ok') throw new Error(`The broker refused the request (${mail.result}).`);
    const purpose = checkout.stage === 'checkin' ? 'checkin' : 'deliver';
    const expires = Date.parse(mail.expires_at ?? '');
    if (purpose === 'deliver' && mail.delivery && expires > Date.now()) {
      const credential = await verifiedVaultWorker<string>(config, 'open-delivery', { wrap: mail.delivery });
      if (expires <= Date.now()) throw new Error('The checkout lease expired.');
      setDelivery({ password: credential, expires });
      setStatus('The credential is ready. Check it in when you finish.');
      return;
    }
    if (mail.challenge && mail.purpose === purpose) {
      const proof = await verifiedVaultWorker<string>(config, 'proof', { challenge: mail.challenge, purpose });
      await vaultRequest(`${txPath}/proof`, 'POST', { proof });
      setStatus('Proof sent to the broker. Refresh when it has answered.');
      return;
    }
    setStatus('Waiting for the broker. Refresh to check again.');
  }

  async function startCheckin() {
    if (!checkout) return;
    await vaultRequest(`/api/transactions/${checkout.request_id}/checkin`, 'POST', {});
    setDelivery(undefined);
    setReveal(false);
    setCheckout({ ...checkout, stage: 'checkin' });
    setStatus('Check-in requested. Refresh to complete the broker’s challenge.');
  }

  async function fileText(file: File) {
    if (file.size > 512 * 1024) throw new Error('This signed file is too large.');
    return file.text();
  }

  return (
    <div className="dr-page kg-wide">
      <div className="dr-header"><h1>Vault</h1></div>
      {error && <p className="dr-alert dr-alert-error" role="alert">{error}</p>}
      {status && <p className="dr-hint" role="status">{status}</p>}
      {!info && !error && <p className="dr-hint" role="status">Loading your vault key…</p>}
      {info && (
        <section className="panel dr-section">
          <h2 className="kg-sub">Your vault key</h2>
          {!unlocked && (!info.sealed || info.sealed.method === 'passphrase') && (
            <form onSubmit={(e) => { e.preventDefault(); void run(() => keyAction('passphrase')); }}>
              <div className="form-group">
                <label htmlFor="vault-passphrase">Vault passphrase</label>
                <input id="vault-passphrase" type="password" value={passphrase} required
                  autoComplete={info.sealed ? 'current-password' : 'new-password'} disabled={busy}
                  onChange={(e) => setPassphrase(e.target.value)} minLength={info.sealed ? undefined : 12} />
              </div>
              {!info.sealed && (
                <div className="form-group">
                  <label htmlFor="vault-confirm-passphrase">Confirm passphrase</label>
                  <input id="vault-confirm-passphrase" type="password" value={confirmation} required
                    autoComplete="new-password" disabled={busy} onChange={(e) => setConfirmation(e.target.value)} />
                </div>
              )}
              <button className="btn-primary" disabled={busy}>{info.sealed ? 'Unlock vault' : 'Create vault key'}</button>
            </form>
          )}
          {!unlocked && hasSuiteKey && (!info.sealed || info.sealed.method === 'kyidentity') && (
            <button className="btn-secondary" type="button" disabled={busy} onClick={() => void run(() => keyAction('kyidentity'))}>
              {info.sealed ? 'Unlock with KyIdentity keyring' : 'Use KyIdentity keyring'}
            </button>
          )}
          {!unlocked && !hasSuiteKey && config.keyring && info.sealed?.method !== 'passphrase' && (
            <button className="btn-secondary" type="button" disabled={busy} onClick={() => void run(() => startKeyring(config))}>
              Sign in with KyIdentity keyring
            </button>
          )}
          {unlocked && (
            <button className="btn-secondary" type="button" disabled={busy || !!checkout || !!pendingEnrollment} onClick={() => void run(async () => {
              await lockVault();
              setUnlocked(false);
              setContext(undefined);
              setAccount('');
              setPassword('');
              setDelivery(undefined);
            })}>Lock vault</button>
          )}
          {info.enrollment && unlocked && enrolledKey && !approved && (
            <>
              <p className="dr-hint">A Custodian must approve this enrollment. Verify these details with them through a trusted channel.</p>
              <dl className="settings-facts">
                <dt>Issuer</dt>
                <dd>{info.issuer}</dd>
                <dt>Subject</dt>
                <dd>{info.subject}</dd>
                <dt>Principal ID</dt>
                <dd className="kg-digest">{enrolledKey.principal_id}</dd>
                <dt>Signing key ID</dt>
                <dd className="kg-digest">{enrolledKey.sig_key_id}</dd>
                <dt>Encryption key ID</dt>
                <dd className="kg-digest">{enrolledKey.enc_key_id}</dd>
              </dl>
              <button className="btn-secondary" type="button" disabled={busy} onClick={() => download('kyguard-enrollment.json', info.enrollment ?? '')}>
                Download enrollment request
              </button>
              <div className="form-group">
                <label htmlFor="vault-signed-enrollment">Upload Custodian-signed enrollment</label>
                <input id="vault-signed-enrollment" type="file" accept=".json,application/json" disabled={busy}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    e.target.value = '';
                    if (file) void run(async () => {
                      const signed = await fileText(file);
                      await vaultRequest('/api/manifests', 'POST', JSON.parse(signed));
                      const next = await vaultRequest<VaultKeyInfo>(vaultKeyPath);
                      setInfo(next);
                      await syncVault(config, next);
                      closeVaultKey();
                      setUnlocked(false);
                      setStatus('Enrollment submitted. Unlock to check approval.');
                    });
                  }} />
              </div>
            </>
          )}
        </section>
      )}
      {unlocked && approved && (
        <section className="panel dr-section">
          <h2 className="kg-sub">Managed credentials</h2>
          {scorecard.error && <p role="alert">{scorecard.error}</p>}
          <div className="form-group">
            <label htmlFor="vault-account">Account</label>
            <select id="vault-account" value={account} disabled={busy || !!checkout || !!pendingEnrollment} onChange={(e) => {
              const id = e.target.value;
              void run(() => selectAccount(id));
            }}>
              <option value="">Choose a managed account</option>
              {scorecard.data?.rows.filter((row) => row.account_kind === 'managed').map((row) =>
                <option key={row.account_id} value={row.account_id}>{row.name} · {row.asset}</option>)}
            </select>
          </div>
          {context?.target && (
            <p className="dr-hint">Verified target <strong>{context.target.identity}</strong> on {context.target.host}:{context.target.port}</p>
          )}
          {context?.can_enroll && !checkout && !pendingEnrollment && (
            <form onSubmit={(e) => void enrollAccount(e)}>
              <div className="form-group">
                <label htmlFor="vault-target-password">Target password</label>
                <input id="vault-target-password" type="password" value={password} required disabled={busy}
                  autoComplete="off" onChange={(e) => setPassword(e.target.value)} />
              </div>
              <button className="btn-primary" disabled={busy}>Enroll credential</button>
            </form>
          )}
          {pendingEnrollment && (
            <>
              <button className="btn-secondary" type="button" disabled={busy}
                onClick={() => download('kyguard-enrollment-approval.json', pendingEnrollment.tx)}>Download request for approval</button>
              <div className="form-group">
                <label htmlFor="vault-enrollment-approval">Load approved enrollment</label>
                <input id="vault-enrollment-approval" type="file" accept=".json,application/json" disabled={busy} onChange={(e) => {
                  const file = e.target.files?.[0];
                  e.target.value = '';
                  if (file) void run(async () => {
                    await refreshTarget();
                    const tx = await verifiedVaultWorker<string>(config, 'attach-approval', {
                      tx: canonicalBytes(await fileText(file)), original: pendingEnrollment.tx,
                    });
                    await submitEnrollment(pendingEnrollment.request_id, { tx, envelope: pendingEnrollment.envelope });
                  });
                }} />
              </div>
              <button className="btn-secondary" type="button" disabled={busy} onClick={() => {
                setPendingEnrollment(undefined);
                setStatus('The unused reservation will expire.');
              }}>Discard enrollment request</button>
            </>
          )}
          {enrollment && (
            <button className="btn-secondary" type="button" disabled={busy} onClick={() => void run(async () => {
              const { state } = await vaultRequest<{ state: string }>(`${path}/enrollments/${enrollment}`);
              await refreshTarget();
              setStatus(`Enrollment is ${state}.`);
            })}>Refresh enrollment</button>
          )}
          {context?.can_checkout && !checkout && !pendingEnrollment && (
            <form onSubmit={(e) => void prepareCheckout(e)}>
              <div className="form-group">
                <label htmlFor="vault-lease-duration">Lease duration (seconds)</label>
                <input id="vault-lease-duration" type="number" min={1} max={context.ttl} required value={ttl} disabled={busy}
                  onChange={(e) => setTTL(e.currentTarget.valueAsNumber)} />
              </div>
              <button className="btn-primary" disabled={busy}>Prepare checkout</button>
            </form>
          )}
          {context?.can_approve && !checkout && !pendingEnrollment && (
            <div className="form-group">
              <label htmlFor="vault-approve-checkout">Review signed request file</label>
              <input id="vault-approve-checkout" type="file" accept=".json,application/json" disabled={busy} onChange={(e) => {
                const file = e.target.files?.[0];
                e.target.value = '';
                if (file) void run(async () => {
                  await refreshTarget();
                  const tx = canonicalBytes(await fileText(file));
                  const review = await verifiedVaultWorker<ApprovalReview>(config, 'review-approval', { tx });
                  setApproval({ tx, review });
                });
              }} />
            </div>
          )}
          {approval && !checkout && !pendingEnrollment && (
            <div className="form-group">
              <p>Requester <strong>{approval.review.requester}</strong> from {approval.review.issuer}</p>
              <p>{approval.review.action === 'enroll' ? 'Enroll a managed credential.' : `Lease requested for ${approval.review.ttl} seconds.`}</p>
              <button className="btn-primary" type="button" disabled={busy} onClick={() => void run(async () => {
                await refreshTarget();
                const signed = await verifiedVaultWorker<string>(config, 'approve', { tx: approval.tx });
                download('kyguard-approved-request.json', signed);
                setApproval(undefined);
                setStatus('Approval signed. Return the downloaded copy to the requester.');
              })}>Sign approval</button>
              <button className="btn-secondary" type="button" disabled={busy} onClick={() => setApproval(undefined)}>Cancel approval</button>
            </div>
          )}
          {checkout?.stage === 'draft' && (
            <>
              {!checkout.approved && (
                <>
                  <button className="btn-secondary" type="button" disabled={busy} onClick={() => download('kyguard-checkout.json', checkout.tx)}>
                    Download checkout request
                  </button>
                  <div className="form-group">
                    <label htmlFor="vault-attach-approval">Load approved checkout</label>
                    <input id="vault-attach-approval" type="file" disabled={busy} accept=".json,application/json" onChange={(e) => {
                      const file = e.target.files?.[0];
                      e.target.value = '';
                      if (file) void run(async () => {
                        await refreshTarget();
                        const tx = await verifiedVaultWorker<string>(config, 'attach-approval', { tx: canonicalBytes(await fileText(file)) });
                        setCheckout({ ...checkout, tx, approved: true });
                      });
                    }} />
                  </div>
                </>
              )}
              <button className="btn-primary" disabled={busy || !checkout.approved} onClick={() => void run(submitCheckout)}>Submit checkout</button>
              <button className="btn-secondary" disabled={busy} onClick={() => setCheckout(undefined)}>Discard request</button>
            </>
          )}
          {checkout && checkout.stage !== 'draft' && (
            <>
              <button className="btn-primary" disabled={busy} onClick={() => void run(advanceCheckout)}>Refresh checkout</button>
              {checkout.stage === 'submitted' && delivery &&
                <button className="btn-secondary" disabled={busy} onClick={() => void run(startCheckin)}>Check in</button>}
              <button className="btn-secondary" disabled={busy} onClick={() => {
                setDelivery(undefined);
                setReveal(false);
                setCheckout(undefined);
                setStatus('Checkout closed here. An open lease will expire on the broker.');
              }}>Close checkout view</button>
            </>
          )}
          {delivery && (
            <div className="form-group">
              <label htmlFor="vault-delivered-password">Checked-out password</label>
              <input id="vault-delivered-password" readOnly autoComplete="off" type={reveal ? 'text' : 'password'} value={delivery.password} />
              <button className="btn-secondary" type="button" onClick={() => setReveal(!reveal)}>{reveal ? 'Hide password' : 'Show password'}</button>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
