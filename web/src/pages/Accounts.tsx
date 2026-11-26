import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Download, Plus, X } from 'lucide-react';
import { ClassBadge, HealthBadge, TrafficLight } from '../components/TrafficLight';
import { secureFetch } from '../api';
import { AttributeDefinition, CLASS_LABEL, HEALTH_LABEL, Scorecard, ScoreRow, scorecardURL, send, useJSON } from '../reporting';

// Accounts is the one reporting page (spec §8.3, §10 item 2): obvious filters, the traffic
// light for exactly those filters, the inventory table and one-click CSV/JSON export.
export const Accounts: React.FC<{ isAdmin: boolean }> = ({ isAdmin }) => {
  const [filter, setFilter] = useState<Record<string, string>>({});
  const card = useJSON<Scorecard>(scorecardURL(filter));
  // Filter choices come from the unfiltered set, so picking one never hides the others.
  const all = useJSON<Scorecard>(scorecardURL({}));
  const defs = useJSON<Record<string, AttributeDefinition[]>>('/api/attributes');
  const label = (entity: string, key: string) => defs.data?.[entity]?.find((d) => d.key === key)?.label || key;
  const [open, setOpen] = useState<string>('');
  const [saved, setSaved] = useState(0); // bumps after a detail closes, so every list reloads
  const set = (k: string, v: string) => setFilter((f) => ({ ...f, [k]: v }));

  const choices = useMemo(() => {
    const rows = all.data?.rows || [];
    const vals = (pick: (r: ScoreRow) => string) => [...new Set(rows.map(pick).filter(Boolean))].sort();
    return {
      pools: vals((r) => r.pool_id),
      attrs: (all.data?.account_attribute_keys || []).map((k) => ({ key: 'attr.' + k, label: label('account', k), values: vals((r) => r.attributes[k]) })),
      owner: (all.data?.owner_attribute_keys || []).map((k) => ({ key: 'owner.' + k, label: 'Owner ' + label('user', k).toLowerCase(), values: vals((r) => r.owner_attributes[k]) })),
    };
  }, [all.data, defs.data]);
  const reload = () => { card.reload(); all.reload(); };
  const active = Object.values(filter).some(Boolean);
  const accountKeys = card.data?.account_attribute_keys ?? [];
  const ownerKeys = card.data?.owner_attribute_keys ?? [];

  return (
    <div className="dr-page kg-wide">
      <div className="dr-header">
        <h1>Accounts</h1>
        <div className="dr-actions">
          <a className="btn btn-secondary" href={scorecardURL(filter, 'csv')} download><Download size={16} />Export CSV</a>
          <a className="btn btn-secondary" href={scorecardURL(filter, 'json')} download><Download size={16} />Export JSON</a>
        </div>
      </div>
      <p className="page-intro">Every privileged account by control level. Exports contain exactly the rows shown and are audited.</p>

      <div className="panel kg-filters" role="search">
        <label className="dr-field">Class
          <select value={filter.class || ''} onChange={(e) => set('class', e.target.value)}>
            <option value="">All</option>
            {Object.entries(CLASS_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        <label className="dr-field">Health
          <select value={filter.health || ''} onChange={(e) => set('health', e.target.value)}>
            <option value="">All</option>
            {Object.entries(HEALTH_LABEL).map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </label>
        {choices.pools.length > 0 && (
          <label className="dr-field">Pool
            <select value={filter.pool || ''} onChange={(e) => set('pool', e.target.value)}>
              <option value="">All</option>
              {choices.pools.map((p) => <option key={p} value={p}>{p.slice(0, 8)}</option>)}
            </select>
          </label>
        )}
        {[...choices.attrs, ...choices.owner].map((a) => (
          <label key={a.key} className="dr-field">{a.label}
            <select value={filter[a.key] || ''} onChange={(e) => set(a.key, e.target.value)}>
              <option value="">All</option>
              {a.values.map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </label>
        ))}
        {active && <button type="button" className="btn-secondary kg-clear" onClick={() => setFilter({})}><X size={14} />Clear</button>}
      </div>

      {card.error && <p role="alert" className="dr-alert dr-alert-error">{card.error}</p>}
      {card.data && (
        <>
          <div className="panel dr-section"><TrafficLight totals={card.data.totals} onPick={(c) => set('class', c)} /></div>
          {isAdmin && <AddAccount onDone={reload} />}
          <div className="panel kg-scroll">
            {card.data.rows.length === 0 ? (
              <p className="dr-hint">{active ? 'No accounts match these filters.' : 'No accounts yet.'}</p>
            ) : (
              <table className="kg-table">
                <thead>
                  <tr>
                    <th>Account</th><th>Class</th><th>Health</th><th>Owner</th><th>Kind</th><th>Min age</th><th>Target</th>
                    {accountKeys.map((k) => <th key={k}>{label('account', k)}</th>)}
                    {ownerKeys.map((k) => <th key={'o' + k}>Owner {label('user', k).toLowerCase()}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {card.data.rows.map((r) => (
                    <tr key={r.account_id}>
                      <td>
                        {isAdmin ? <button type="button" className="kg-link" onClick={() => setOpen(r.account_id)}>{r.asset} / {r.name}</button> : <span>{r.asset} / {r.name}</span>}
                      </td>
                      <td><ClassBadge value={r.class} /></td>
                      <td><HealthBadge value={r.health} reason={r.health_reason} /></td>
                      <td>{r.owner || '—'}</td>
                      <td>{r.account_kind}</td>
                      <td>{r.min_password_age_seconds == null ? '—' : `${Math.round(r.min_password_age_seconds / 3600)} h`}</td>
                      <td className="dr-mono" title={r.target_descriptor_digest}>{r.target_descriptor_digest ? r.target_descriptor_digest.slice(0, 12) : '—'}</td>
                      {accountKeys.map((k) => <td key={k}>{r.attributes[k] || '—'}</td>)}
                      {ownerKeys.map((k) => <td key={'o' + k}>{r.owner_attributes[k] || '—'}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </>
      )}
      {isAdmin && (card.data?.totals.decommissioned ?? 0) > 0 && <Retired version={saved} onOpen={setOpen} />}
      {open && <AccountDetail id={open} onClose={() => { setOpen(''); reload(); setSaved((n) => n + 1); }} />}
    </div>
  );
};

const AddAccount: React.FC<{ onDone: () => void }> = ({ onDone }) => {
  const assets = useJSON<{ ID: string; Name: string }[]>('/api/assets');
  const [shown, setShown] = useState(false);
  const [asset, setAsset] = useState('');
  const [newAsset, setNewAsset] = useState('');
  const [name, setName] = useState('');
  const [kind, setKind] = useState<'managed' | 'vaulted'>('managed');
  const [pool, setPool] = useState('');
  const [err, setErr] = useState('');
  // One submission at a time: a second click would POST a second asset and account.
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);

  if (!shown) {
    return <div className="dr-section"><button type="button" className="btn-secondary" onClick={() => setShown(true)}><Plus size={16} />Add account</button></div>;
  }
  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    try {
      await create();
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  const create = async () => {
    let assetID = asset;
    if (!assetID) {
      const r = await fetchJSON('POST', '/api/assets', { name: newAsset });
      if (typeof r === 'string') { setErr(r); return; }
      assetID = r.ID;
      setAsset(assetID); // a retry or the next account reuses it
      assets.reload();
    }
    const body: Record<string, string> = { asset_id: assetID, name, account_kind: kind };
    if (kind === 'managed' && pool) body.pool_id = pool;
    const fail = await send('POST', '/api/accounts', body);
    setErr(fail);
    if (!fail) { setName(''); setShown(false); onDone(); }
  };
  return (
    <form className="panel dr-section" onSubmit={submit} aria-label="Add account">
      <div className="dr-row">
        <label className="dr-field">Asset
          <select value={asset} onChange={(e) => setAsset(e.target.value)}>
            <option value="">New asset…</option>
            {(assets.data || []).map((a) => <option key={a.ID} value={a.ID}>{a.Name}</option>)}
          </select>
        </label>
        {!asset && <label className="dr-field">New asset name<input value={newAsset} onChange={(e) => setNewAsset(e.target.value)} required /></label>}
        <label className="dr-field">Account name<input value={name} onChange={(e) => setName(e.target.value)} required /></label>
        <label className="dr-field dr-narrow">Kind
          <select value={kind} onChange={(e) => setKind(e.target.value as 'managed' | 'vaulted')}>
            <option value="managed">managed</option><option value="vaulted">vaulted</option>
          </select>
        </label>
        {kind === 'managed' && <label className="dr-field">Broker pool ID<input value={pool} onChange={(e) => setPool(e.target.value)} placeholder="optional" /></label>}
      </div>
      {err && <p role="alert" className="dr-danger">{err}</p>}
      <div className="dr-actions"><button type="submit" disabled={busy}>Add</button><button type="button" className="btn-secondary" onClick={() => setShown(false)}>Cancel</button></div>
    </form>
  );
};

async function fetchJSON(method: string, url: string, body: unknown): Promise<any | string> {
  let r: Response;
  try {
    r = await secureFetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  } catch {
    return 'Could not reach the server; nothing was saved.';
  }
  const j = await r.json().catch(() => ({}));
  return r.ok ? j : j.error || `HTTP ${r.status}`;
}

interface Detail {
  account: { ID: string; Name: string; AccountKind: string; Status: string; asset_name: string; owner_user_id: string; min_password_age_seconds: number | null };
  descriptors: { digest: string; connector_type: string; authenticated_target_identity: string; host: string; port: number; tls_ca_sha256?: string; ssh_host_key_sha256?: string }[];
  attributes: Record<string, string>;
}

// AccountDetail edits inventory metadata. Credentials are never shown or entered here: they
// live only in kyguard-cli (spec §10).
const AccountDetail: React.FC<{ id: string; onClose: () => void }> = ({ id, onClose }) => {
  const detail = useJSON<Detail>(`/api/accounts/${id}`, { keepOnTemporaryError: true });
  const defs = useJSON<Record<string, AttributeDefinition[]>>('/api/attributes');
  const [err, setErr] = useState('');
  const [closing, setClosing] = useState(false);
  const ref = useRef<HTMLDialogElement>(null);
  // Writes still in flight: closing waits for them, so the page reloads after they land.
  const pending = useRef(new Set<Promise<string>>());
  const act = async (fail: Promise<string>) => {
    pending.current.add(fail);
    try {
      const f = await fail;
      setErr(f);
      if (!f) detail.reload();
      return f;
    } finally {
      pending.current.delete(fail);
    }
  };
  const close = async () => {
    if (closing) return;
    // Escape can arrive while a text edit still has focus. Start its blur save before waiting.
    const focused = document.activeElement;
    if (focused instanceof HTMLInputElement && ref.current?.contains(focused)) focused.blur();
    setClosing(true);
    const error = (await Promise.all(pending.current)).find(Boolean);
    if (error) {
      setErr(error);
      setClosing(false);
      return;
    }
    onClose();
  };
  const d = detail.data;
  useEffect(() => {
    const dlg = ref.current;
    if (dlg && !dlg.open) dlg.showModal?.();
    return () => dlg?.close?.();
  }, []);

  return (
    <dialog ref={ref} className="modal-window kg-detail" aria-label="Account details" aria-busy={closing}
      onCancel={(event) => { event.preventDefault(); void close(); }}>
        <div className="panel-header">
          <h3>{d ? `${d.account.asset_name} / ${d.account.Name}` : 'Account'}</h3>
          <button type="button" className="btn-secondary" onClick={close} disabled={closing} aria-label="Close"><X size={16} /></button>
        </div>
        {detail.error && <p role="alert" className="dr-danger">{detail.error}</p>}
        {d && (
          <div className="dr-stack" inert={closing}>
            <OwnerPicker current={d.account.owner_user_id} onPick={(owner) => act(send('PATCH', `/api/accounts/${id}`, { owner_user_id: owner }))} />
            {(defs.data?.account || []).map((a) => {
              const stored = d.attributes[a.key] || '';
              const onSave = (value: string) => act(send('PUT', `/api/attributes/${a.id}/values/${id}`, { value }));
              return (
                <label key={a.id} className="dr-field">{a.label}
                  {a.type === 'enum'
                    ? <EnumAttribute stored={stored} options={a.enum_values} onSave={onSave} />
                    : <TextAttribute stored={stored} onSave={onSave} />}
                </label>
              );
            })}
            <div>
              <h4 className="kg-sub">Target descriptors</h4>
              {d.descriptors.length === 0 ? <p className="dr-hint">None uploaded. Upload one with PUT /api/accounts/{id}/target-descriptor.</p> : (
                <dl className="settings-facts">
                  {d.descriptors.map((t) => (
                    <React.Fragment key={t.digest}>
                      <dt>{t.connector_type}</dt>
                      <dd>
                        {t.authenticated_target_identity} @ {t.host}:{t.port}
                        <div className="dr-mono kg-digest">digest {t.digest}</div>
                        {t.tls_ca_sha256 && <div className="dr-mono kg-digest">CA SHA-256 {t.tls_ca_sha256}</div>}
                        {t.ssh_host_key_sha256 && <div className="dr-mono kg-digest">host key SHA-256 {t.ssh_host_key_sha256}</div>}
                      </dd>
                    </React.Fragment>
                  ))}
                </dl>
              )}
            </div>
            <p className="dr-hint">Minimum password age: {d.account.min_password_age_seconds == null ? 'not reported yet' : `${d.account.min_password_age_seconds} s`}</p>
            {err && <p role="alert" className="dr-danger">{err}</p>}
            <div className="dr-actions">
              {d.account.Status === 'active'
                ? <button type="button" className="btn-danger" onClick={() => window.confirm('Decommission this account? It leaves the traffic light.') && act(send('PATCH', `/api/accounts/${id}`, { status: 'decommissioned' }))}>Decommission</button>
                : <button type="button" className="btn-secondary" onClick={() => act(send('PATCH', `/api/accounts/${id}`, { status: 'active' }))}>Reactivate</button>}
            </div>
          </div>
        )}
    </dialog>
  );
};

const TextAttribute: React.FC<{ stored: string; onSave: (value: string) => Promise<string> }> = ({ stored, onSave }) => {
  const ref = useRef<HTMLInputElement>(null);
  const saved = useRef(stored);
  useEffect(() => {
    // Refresh untouched text without replacing the input or overwriting a newer edit.
    const input = ref.current;
    if (input && input.value === saved.current) input.value = stored;
    saved.current = stored;
  }, [stored]);

  const saveOnBlur = async (event: React.FocusEvent<HTMLInputElement>) => {
    const input = event.currentTarget;
    const value = input.value;
    if (input.readOnly || value === saved.current) return;
    input.readOnly = true;
    try {
      if (await onSave(value)) input.value = saved.current;
      else saved.current = value;
    } finally {
      input.readOnly = false;
    }
  };

  return <input ref={ref} defaultValue={stored} onBlur={saveOnBlur} />;
};

const EnumAttribute: React.FC<{
  stored: string;
  options: string[];
  onSave: (value: string) => Promise<string>;
}> = ({ stored, options, onSave }) => {
  const ref = useRef<HTMLSelectElement>(null);
  const saved = useRef(stored);
  useEffect(() => {
    const select = ref.current;
    if (select && !select.disabled) select.value = stored;
    saved.current = stored;
  }, [stored]);

  const saveOnChange = async (event: React.ChangeEvent<HTMLSelectElement>) => {
    const select = event.currentTarget;
    const value = select.value;
    if (select.disabled || value === saved.current) return;
    select.disabled = true;
    try {
      if (!(await onSave(value))) saved.current = value;
      select.value = saved.current;
    } finally {
      select.disabled = false;
    }
  };

  return (
    <select ref={ref} defaultValue={stored} onChange={saveOnChange}>
      <option value="">—</option>
      {options.map((value) => <option key={value} value={value}>{value}</option>)}
    </select>
  );
};

// OwnerPicker searches the whole directory on the server, so any user can be chosen.
const OwnerPicker: React.FC<{ current: string; onPick: (id: string) => void }> = ({ current, onPick }) => {
  const [q, setQ] = useState('');
  const found = useJSON<{ users: { id: string; username: string; display_name: string }[] }>(
    q.trim().length >= 2 ? `/api/admin/users?limit=20&search=${encodeURIComponent(q.trim())}` : null);
  return (
    <div className="dr-field">
      <span>Owner: <span className="dr-mono">{current || 'none'}</span>
        {current && <button type="button" className="btn-secondary kg-inline" onClick={() => onPick('')}>Clear</button>}</span>
      <input aria-label="Find owner" placeholder="Type 2+ letters of a name" value={q} onChange={(e) => setQ(e.target.value)} />
      {(found.data?.users || []).length > 0 && (
        <ul className="kg-plain kg-results">
          {found.data!.users.map((u) => (
            <li key={u.id}><button type="button" className="kg-link" onClick={() => { onPick(u.id); setQ(''); }}>{u.username}{u.display_name && u.display_name !== u.username ? ` (${u.display_name})` : ''}</button></li>
          ))}
        </ul>
      )}
    </div>
  );
};

// Retired lists decommissioned accounts, which the traffic light counts but never shows, so an
// admin can open one and reactivate it.
const Retired: React.FC<{ version: number; onOpen: (id: string) => void }> = ({ version, onOpen }) => {
  const [shown, setShown] = useState(false);
  const list = useJSON<{ ID: string; Name: string; asset_name: string }[]>(shown ? '/api/accounts?status=decommissioned' : null);
  const { reload } = list;
  useEffect(() => { if (version > 0) reload(); }, [version, reload]); // a status may have changed
  return (
    <div className="panel dr-section kg-top">
      <button type="button" className="btn-secondary" aria-expanded={shown} onClick={() => setShown(!shown)}>{shown ? 'Hide' : 'Show'} decommissioned accounts</button>
      {list.error && <p role="alert" className="dr-danger">{list.error}</p>}
      {shown && list.data && (
        <ul className="kg-plain kg-results">
          {list.data.map((a) => <li key={a.ID}><button type="button" className="kg-link" onClick={() => onOpen(a.ID)}>{a.asset_name} / {a.Name}</button></li>)}
        </ul>
      )}
    </div>
  );
};
