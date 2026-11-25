import React, { useState } from 'react';
import { Trash2 } from 'lucide-react';
import { localInput, Scorecard, send, useJSON } from '../reporting';

interface Draft {
  id: string;
  account_id: string;
  account: string;
  epoch: number;
  digest: string;
  signatures: number;
  status: 'needs_signatures' | 'ready' | 'stale';
  code?: string;
  updated_at: string;
}

interface Principal { principal_id: string; issuer: string; subject: string; active_keys: number }

// Policies drafts the next PolicyManifest of an account and shows its digest for Custodian
// signing in kyguard-cli (spec §10 item 4). The browser signs nothing.
export const Policies: React.FC<{ isAdmin: boolean }> = ({ isAdmin }) => {
  const drafts = useJSON<Draft[]>('/api/policy-drafts');
  const [delErr, setDelErr] = useState('');
  const remove = async (id: string) => {
    if (!window.confirm('Delete this draft and its signatures?')) return;
    const fail = await send('DELETE', `/api/policy-drafts/${id}`);
    setDelErr(fail);
    if (!fail) drafts.reload();
  };
  const trust = useJSON<{ imported: boolean; threshold?: number; custodians?: number; escrow_default_enabled?: boolean }>('/api/trust');

  return (
    <div className="dr-page kg-wide">
      <div className="dr-header"><h1>Policies</h1></div>
      <p className="page-intro">
        A draft takes effect only after {trust.data?.threshold ?? 'M'} of {trust.data?.custodians ?? 'N'} Custodians sign it with
        <code> kyguard-cli sign</code>. Check the digest there against the one shown here.
      </p>
      {drafts.error && <p role="alert" className="dr-alert dr-alert-error">{drafts.error}</p>}
      {delErr && <p role="alert" className="dr-alert dr-alert-error">{delErr}</p>}
      <div className="panel dr-section kg-scroll">
        <h3 className="kg-sub">Drafts awaiting signatures</h3>
        {(drafts.data || []).length === 0 ? <p className="dr-hint">No drafts.</p> : (
          <table className="kg-table">
            <thead><tr><th>Account</th><th>Epoch</th><th>Digest</th><th>Signatures</th><th>Status</th>{isAdmin && <th />}</tr></thead>
            <tbody>
              {drafts.data!.map((d) => (
                <tr key={d.id}>
                  <td>{d.account}</td>
                  <td>{d.epoch}</td>
                  <td className="dr-mono kg-digest">{d.digest}</td>
                  <td>{d.signatures}{trust.data?.threshold ? ` / ${trust.data.threshold}` : ''}</td>
                  <td>{d.status === 'stale'
                    ? <span className="badge badge-danger" title={d.code}>Stale{d.code ? `: ${d.code}` : ''}</span>
                    : d.status === 'ready'
                      ? <span className="badge badge-success" title="Fully signed; signing it again retries admission">Ready</span>
                      : <span className="badge badge-accent">Needs signatures</span>}</td>
                  {isAdmin && <td><button type="button" className="btn-secondary" aria-label="Delete draft" onClick={() => remove(d.id)}><Trash2 size={14} /></button></td>}
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      {isAdmin && <DraftForm escrowDefault={!!trust.data?.escrow_default_enabled} onSaved={drafts.reload} />}
    </div>
  );
};

const DraftForm: React.FC<{ escrowDefault: boolean; onSaved: () => void }> = ({ escrowDefault, onSaved }) => {
  const accounts = useJSON<Scorecard>('/api/reports/scorecard');
  const principals = useJSON<Principal[]>('/api/principals');
  const [account, setAccount] = useState('');
  const [mode, setMode] = useState('ephemeral');
  const [target, setTarget] = useState('');
  const [lists, setLists] = useState<Record<string, string[]>>({ users: [], approvers: [], enrollers: [], standing: [] });
  const [approvals, setApprovals] = useState(0);
  const [ttl, setTTL] = useState(3600);
  const [schedule, setSchedule] = useState({ on: true, anchor: localInput(new Date()), hours: 24 });
  const [escrow, setEscrow] = useState<boolean | null>(null);
  const [err, setErr] = useState('');
  const [saved, setSaved] = useState('');
  const descs = useJSON<{ descriptors: { digest: string; host: string; connector_type: string }[] }>(account ? `/api/accounts/${account}` : null);
  const row = accounts.data?.rows.find((r) => r.account_id === account);
  const managed = row?.account_kind === 'managed';

  const toggle = (list: string, id: string) => setLists((l) => ({ ...l, [list]: l[list].includes(id) ? l[list].filter((x) => x !== id) : [...l[list], id] }));
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const body: Record<string, unknown> = {
      allowed_user_principal_ids: lists.users, allowed_approver_principal_ids: lists.approvers,
      required_approver_count: approvals, max_checkout_ttl_seconds: ttl, recovery_escrow_enabled: escrow ?? escrowDefault,
    };
    if (managed && schedule.on && Number.isNaN(new Date(schedule.anchor).getTime())) {
      setErr('Choose when the first rotation runs.');
      return;
    }
    if (managed) {
      Object.assign(body, {
        checkout_mode: mode, target_descriptor_digest: target, enroller_principal_ids: lists.enrollers,
        standing_recipient_principal_ids: lists.standing, auto_standing_release: false,
        rotation_schedule: schedule.on ? { anchor_utc: new Date(schedule.anchor).toISOString().replace(/\.\d{3}Z$/, 'Z'), interval_seconds: schedule.hours * 3600 } : null,
      });
    }
    const fail = await send('PUT', `/api/accounts/${account}/policy-draft`, body);
    setErr(fail);
    setSaved(fail ? '' : 'Draft saved. Custodians can now sign it.');
    if (!fail) onSaved();
  };
  const picker = (list: string, label: string) => (
    <fieldset className="kg-pick">
      <legend>{label}</legend>
      {(principals.data || []).length === 0 ? <p className="dr-hint">No enrolled principals yet (kyguard-cli enroll).</p> :
        principals.data!.map((p) => (
          <label key={p.principal_id} className="kg-check">
            <input type="checkbox" checked={lists[list].includes(p.principal_id)} onChange={() => toggle(list, p.principal_id)} />
            <span>{p.subject}</span><span className="dr-mono kg-digest">{p.principal_id.slice(0, 8)}</span>
          </label>
        ))}
    </fieldset>
  );

  return (
    <form className="panel dr-section" onSubmit={submit} aria-label="New policy draft">
      <h3 className="kg-sub">New draft</h3>
      <div className="dr-row">
        <label className="dr-field">Account
          <select value={account} onChange={(e) => { setAccount(e.target.value); setTarget(''); }} required>
            <option value="">Choose…</option>
            {(accounts.data?.rows || []).map((r) => <option key={r.account_id} value={r.account_id}>{r.asset} / {r.name} ({r.account_kind})</option>)}
          </select>
        </label>
        {managed && (
          <>
            <label className="dr-field">Checkout mode
              <select value={mode} onChange={(e) => setMode(e.target.value)}>
                <option value="ephemeral">ephemeral</option><option value="standing">standing</option>
              </select>
            </label>
            <label className="dr-field">Target descriptor
              <select value={target} onChange={(e) => setTarget(e.target.value)} required>
                <option value="">Choose…</option>
                {(descs.data?.descriptors || []).map((d) => <option key={d.digest} value={d.digest}>{d.connector_type} {d.host} ({d.digest.slice(0, 12)})</option>)}
              </select>
            </label>
          </>
        )}
      </div>
      {account && (
        <>
          <div className="dr-two">
            {picker('users', managed ? 'Requesters' : 'Recipients')}
            {picker('approvers', 'Approvers')}
            {managed && picker('enrollers', 'Enrollers')}
            {managed && mode === 'standing' && picker('standing', 'Standing recipients')}
          </div>
          <div className="dr-row">
            <label className="dr-field dr-narrow">Approvals needed<input type="number" min={0} value={approvals} onChange={(e) => setApprovals(+e.target.value)} /></label>
            <label className="dr-field dr-narrow">Max checkout (s)<input type="number" min={0} value={ttl} onChange={(e) => setTTL(+e.target.value)} /></label>
            {managed && (
              <>
                <label className="kg-check"><input type="checkbox" checked={schedule.on} onChange={(e) => setSchedule({ ...schedule, on: e.target.checked })} /><span>Rotate on a schedule</span></label>
                {schedule.on && <label className="dr-field">First rotation (local time)<input type="datetime-local" required value={schedule.anchor} onChange={(e) => setSchedule({ ...schedule, anchor: e.target.value })} /></label>}
                {schedule.on && <label className="dr-field dr-narrow">Every (hours)<input type="number" min={1} value={schedule.hours} onChange={(e) => setSchedule({ ...schedule, hours: +e.target.value })} /></label>}
              </>
            )}
            <label className="kg-check"><input type="checkbox" checked={escrow ?? escrowDefault} onChange={(e) => setEscrow(e.target.checked)} /><span>Recovery escrow</span></label>
          </div>
        </>
      )}
      {err && <p role="alert" className="dr-danger">{err}</p>}
      {saved && <p role="status" className="dr-ok">{saved}</p>}
      <button type="submit" disabled={!account}>Save draft</button>
    </form>
  );
};
