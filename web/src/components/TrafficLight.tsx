import React from 'react';
import { CLASS_LABEL, HEALTH_LABEL, Totals, TrafficClass } from '../reporting';

const ORDER: TrafficClass[] = ['green', 'yellow', 'red'];

export const ClassBadge: React.FC<{ value: TrafficClass }> = ({ value }) => (
  <span className={`badge tl-badge tl-${value}`}>{CLASS_LABEL[value]}</span>
);

export const HealthBadge: React.FC<{ value: string; reason?: string }> = ({ value, reason }) => (
  <span className={`badge ${value === 'healthy' ? 'dr-badge-muted' : value === 'checkout_open' || value === 'pending_first_rotation' ? 'badge-accent' : 'badge-danger'}`} title={reason || undefined}>
    {HEALTH_LABEL[value] || value}
  </span>
);

// TrafficLight shows the three classes as one bar that always fills 100% (spec §8.1).
export const TrafficLight: React.FC<{ totals: Totals; onPick?: (c: TrafficClass) => void }> = ({ totals, onPick }) => (
  <div className="tl">
    <div className="tl-bar" role="img" aria-label={ORDER.map((c) => `${CLASS_LABEL[c]} ${totals.percent[c]}%`).join(', ')}>
      {ORDER.map((c) => totals.classes[c] > 0 && (
        <span key={c} className={`tl-seg tl-${c}`} style={{ width: `${totals.percent[c]}%` }} />
      ))}
    </div>
    <div className="tl-legend">
      {ORDER.map((c) => (
        <button key={c} type="button" className="tl-item" onClick={onPick ? () => onPick(c) : undefined} disabled={!onPick}>
          <span className={`tl-dot tl-${c}`} aria-hidden="true" />
          <span className="tl-count">{totals.classes[c]}</span>
          <span className="tl-name">{CLASS_LABEL[c]}</span>
          <span className="tl-pct">{totals.percent[c]}%</span>
        </button>
      ))}
    </div>
    <p className="dr-hint">
      {totals.active} active accounts{totals.decommissioned > 0 ? `; ${totals.decommissioned} decommissioned, not counted` : ''}.
    </p>
  </div>
);
