import React from 'react';
import { useJSON } from '../reporting';

interface Run { operation_id: string; account_id: string; broker_id: string; secret_version: number; state: string; updated_at: string }
interface Lease { request_id: string; account_id: string; broker_id: string; state: string; close_reason: string; opened_at: string; expires_at: string }

const RUN_BAD = ['write_outcome_unknown', 'aborted'];
const when = (s: string) => new Date(s).toLocaleString();

// Jobs shows rotation runs and checkout leases as the brokers report them (spec §10 item 5).
export const Jobs: React.FC = () => {
  const jobs = useJSON<{ runs: Run[]; leases: Lease[] }>('/api/jobs');
  return (
    <div className="dr-page kg-wide">
      <div className="dr-header"><h1>Jobs</h1><button type="button" className="btn-secondary" onClick={jobs.reload}>Refresh</button></div>
      <p className="page-intro">Brokers run rotations on their own schedule; this is what they reported.</p>
      {jobs.error && <p role="alert" className="dr-alert dr-alert-error">{jobs.error}</p>}
      <div className="panel dr-section kg-scroll">
        <h3 className="kg-sub">Rotation runs</h3>
        {(jobs.data?.runs || []).length === 0 ? <p className="dr-hint">No rotation runs yet.</p> : (
          <table className="kg-table">
            <thead><tr><th>Updated</th><th>Account</th><th>Version</th><th>State</th><th>Operation</th></tr></thead>
            <tbody>
              {jobs.data!.runs.map((r) => (
                <tr key={r.account_id + r.operation_id}>
                  <td>{when(r.updated_at)}</td>
                  <td className="dr-mono">{r.account_id.slice(0, 8)}</td>
                  <td>{r.secret_version}</td>
                  <td><span className={`badge ${RUN_BAD.includes(r.state) ? 'badge-danger' : r.state === 'release_authorized' ? 'badge-success' : 'badge-accent'}`}>{r.state}</span></td>
                  <td className="dr-mono kg-digest">{r.operation_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
      <div className="panel kg-scroll">
        <h3 className="kg-sub">Checkout leases</h3>
        {(jobs.data?.leases || []).length === 0 ? <p className="dr-hint">No checkout leases.</p> : (
          <table className="kg-table">
            <thead><tr><th>Opened</th><th>Expires</th><th>Account</th><th>State</th><th>Reason</th></tr></thead>
            <tbody>
              {jobs.data!.leases.map((l) => (
                <tr key={l.request_id}>
                  <td>{when(l.opened_at)}</td>
                  <td>{when(l.expires_at)}</td>
                  <td className="dr-mono">{l.account_id.slice(0, 8)}</td>
                  <td><span className={`badge ${l.state === 'closed' ? 'dr-badge-muted' : 'badge-accent'}`}>{l.state}</span></td>
                  <td>{l.close_reason || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
