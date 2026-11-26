import React, { useState } from 'react';
import { Trash2 } from 'lucide-react';
import { AttributeDefinition, send, useJSON, useReportingWrite } from '../reporting';

// Attributes lists definitions for accounts and users (spec §8.2, §10 item 3). SCIM-synced
// ones are read-only; admins add and remove their own.
export const Attributes: React.FC<{ isAdmin: boolean }> = ({ isAdmin }) => {
  const { pending, revision, run } = useReportingWrite('attribute-definitions');
  const defs = useJSON<Record<'account' | 'user', AttributeDefinition[]>>('/api/attributes', { writeRevision: revision });
  const [err, setErr] = useState('');
  const [form, setForm] = useState({ entity: 'account', key: '', label: '', type: 'string', values: '' });

  const submit = (e: React.FormEvent) => {
    e.preventDefault();
    void run(create);
  };
  const create = async () => {
    const body: Record<string, unknown> = { entity: form.entity, key: form.key, label: form.label, type: form.type };
    if (form.type === 'enum') body.enum_values = form.values.split(',').map((v) => v.trim()).filter(Boolean);
    const fail = await send('POST', '/api/attributes', body);
    setErr(fail);
    if (!fail) setForm((current) => current === form ? { ...current, key: '', label: '', values: '' } : current);
    return !fail;
  };
  const remove = (d: AttributeDefinition) => run(async () => {
    if (!window.confirm(`Delete ${d.label} and every value it holds?`)) return false;
    const fail = await send('DELETE', `/api/attributes/${d.id}`);
    setErr(fail);
    return !fail;
  });

  return (
    <div className="dr-page">
      <div className="dr-header"><h1>Attributes</h1></div>
      <p className="page-intro">Labels that reports filter on. Owner attributes reach accounts through the account's owner.</p>
      {defs.error && <p role="alert" className="dr-alert dr-alert-error">{defs.error}</p>}
      <div className="dr-two">
        {(['account', 'user'] as const).map((entity) => (
          <div key={entity} className="panel">
            <h3 className="kg-sub">{entity === 'account' ? 'Account attributes' : 'User attributes'}</h3>
            {(defs.data?.[entity] || []).length === 0 ? <p className="dr-hint">None yet.</p> : (
              <table className="kg-table">
                <thead><tr><th>Label</th><th>Key</th><th>Type</th><th>Source</th>{isAdmin && <th />}</tr></thead>
                <tbody>
                  {defs.data![entity].map((d) => (
                    <tr key={d.id}>
                      <td>{d.label}</td>
                      <td className="dr-mono">{d.key}</td>
                      <td>{d.type === 'enum' ? `enum: ${d.enum_values.join(', ')}` : 'string'}</td>
                      <td><span className={`badge ${d.source === 'scim' ? 'badge-accent' : 'dr-badge-muted'}`}>{d.source === 'scim' ? 'SCIM, read-only' : 'Admin'}</span></td>
                      {isAdmin && <td>{d.source === 'admin' && <button type="button" className="btn-secondary" aria-label={`Delete ${d.label}`} disabled={pending} onClick={() => remove(d)}><Trash2 size={14} /></button>}</td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {entity === 'user' && <p className="dr-hint">Department, manager and title come from SCIM (Enterprise User extension).</p>}
          </div>
        ))}
      </div>
      {isAdmin && (
        <form className="panel dr-section kg-top" onSubmit={submit} aria-label="New attribute">
          <h3 className="kg-sub">New attribute</h3>
          <div className="dr-row">
            <label className="dr-field dr-narrow">For
              <select value={form.entity} onChange={(e) => setForm({ ...form, entity: e.target.value })}>
                <option value="account">accounts</option><option value="user">users</option>
              </select>
            </label>
            <label className="dr-field">Label<input value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} required /></label>
            <label className="dr-field">Key<input value={form.key} pattern="[a-z][a-z0-9_]{0,63}" title="lowercase letters, digits and _" onChange={(e) => setForm({ ...form, key: e.target.value })} required /></label>
            <label className="dr-field dr-narrow">Type
              <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value })}>
                <option value="string">string</option><option value="enum">enum</option>
              </select>
            </label>
            {form.type === 'enum' && <label className="dr-field">Values (comma separated)<input value={form.values} onChange={(e) => setForm({ ...form, values: e.target.value })} required /></label>}
          </div>
          {err && <p role="alert" className="dr-danger">{err}</p>}
          <button type="submit" disabled={pending}>Add attribute</button>
        </form>
      )}
    </div>
  );
};
