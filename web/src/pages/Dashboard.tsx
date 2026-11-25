import React from 'react';
import { Key, Archive, Database, Users, CheckCircle2, ArrowRight } from 'lucide-react';
import { TrafficLight } from '../components/TrafficLight';
import { HEALTH_LABEL, Scorecard, useJSON } from '../reporting';

interface DashboardProps {
  settings: any;
  user: any;
  onNavigate: (tab: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({ settings, user, onNavigate }) => {
  const card = useJSON<Scorecard>('/api/reports/scorecard');
  const trust = useJSON<{ imported: boolean; threshold?: number; custodians?: number }>('/api/trust');
  const totals = card.data?.totals;
  const health = Object.entries(totals?.health || {}).filter(([h]) => h !== 'healthy');
  const cards = [
    {
      title: 'Feature 0: KyBackup & Recovery',
      desc: 'Encrypted capsule container generation and automated sandboxed restore drills.',
      // Backup readiness lives on the backup page; no status is claimed here.
      status: '',
      statusType: 'neutral',
      icon: Archive,
      action: () => onNavigate('backup'),
      actionLabel: 'Run Restore Drill',
    },
    {
      title: 'SCIM 2.0 Inbound Provisioning',
      desc: 'RFC 7643/7644 automatic user and group provisioning from enterprise IdPs.',
      status: settings?.scim_enabled ? 'Active' : 'Disabled',
      statusType: settings?.scim_enabled ? 'success' : 'neutral',
      icon: Users,
      action: () => onNavigate('scim'),
      actionLabel: 'Manage Directory',
    },
    {
      title: 'Single Sign-On & Federation',
      desc: 'KySignOn and generic OIDC, with TOTP step-up on every login.',
      status: settings?.sso_enabled ? 'Enabled' : 'Disabled',
      statusType: settings?.sso_enabled ? 'success' : 'neutral',
      icon: Key,
      action: () => onNavigate('settings'),
      actionLabel: 'SSO Settings',
    },
    {
      title: 'Pluggable Database Engine',
      desc: `Current storage backend: ${settings?.db_driver?.toUpperCase() || 'SQLITE'} (zero-CGO with WAL mode & foreign keys).`,
      status: `${settings?.db_driver || 'sqlite'} (active)`,
      statusType: 'neutral',
      icon: Database,
      action: () => onNavigate('settings'),
      actionLabel: 'Database Config',
    },
  ];

  return (
    <div className="dr-page">
      <div className="dr-header"><h1>Welcome, {user?.display_name || user?.username}!</h1></div>
      <p className="page-intro">{settings?.app_name || 'KyGuard'}: privileged access management.</p>

      {trust.data?.imported && trust.data.threshold === 1 && trust.data.custodians === 1 && (
        <p role="alert" className="dr-alert dr-alert-warn">One Custodian signs alone (1 of 1): a single lost or stolen key file controls every policy. Add Custodians and raise the threshold.</p>
      )}
      {card.error && <p role="alert" className="dr-alert dr-alert-error">{card.error}</p>}
      {totals && (
        <div className="panel dr-section">
          <div className="panel-header">
            <h3>Control level</h3>
            <button type="button" className="btn-secondary" onClick={() => onNavigate('accounts')}><span>Open accounts</span><ArrowRight size={14} /></button>
          </div>
          <TrafficLight totals={totals} />
          {health.length > 0 && (
            <ul className="tl-legend kg-plain" aria-label="Health">
              {health.map(([h, n]) => <li key={h} className={`badge ${h === 'quarantined' || h === 'auth_failed' ? 'badge-danger' : 'badge-accent'}`}>{HEALTH_LABEL[h] || h}: {n}</li>)}
            </ul>
          )}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        {cards.map((c, i) => {
          const Icon = c.icon;
          return (
            <div key={i} className="panel" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                  <div style={{ padding: '8px', background: 'var(--panel-hover)', borderRadius: '8px', color: 'var(--ink-strong)' }}>
                    <Icon size={20} />
                  </div>
                  {c.status && <span className={`badge badge-${c.statusType === 'success' ? 'success' : c.statusType === 'accent' ? 'accent' : 'secondary'}`}>
                    {c.statusType === 'success' && <CheckCircle2 size={12} />}
                    {c.status}
                  </span>}
                </div>
                <h3 style={{ fontSize: '16px', marginBottom: '6px' }}>{c.title}</h3>
                <p style={{ color: 'var(--ink)', fontSize: '13px', lineHeight: 1.5 }}>{c.desc}</p>
              </div>

              <div style={{ marginTop: '20px', borderTop: '1px solid var(--line)', paddingTop: '12px' }}>
                <button
                  type="button"
                  className="btn-secondary"
                  style={{ width: '100%', justifyContent: 'space-between', fontSize: '13px' }}
                  onClick={c.action}
                >
                  <span>{c.actionLabel}</span>
                  <ArrowRight size={14} />
                </button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
