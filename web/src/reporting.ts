import { useCallback, useEffect, useRef, useState } from 'react';
import { secureFetch } from './api';

// Shapes of the reporting API (docs/INTERFACES.md, spec §8). The browser never handles a
// credential: every value here is metadata.
export type TrafficClass = 'green' | 'yellow' | 'red';

export interface ScoreRow {
  account_id: string;
  asset: string;
  name: string;
  account_kind: 'managed' | 'vaulted';
  pool_id: string;
  class: TrafficClass;
  health: string;
  health_reason: string;
  owner_user_id: string;
  owner: string;
  min_password_age_seconds: number | null;
  target_descriptor_digest: string;
  last_release: string | null;
  attributes: Record<string, string>;
  owner_attributes: Record<string, string>;
}

export interface Totals {
  active: number;
  decommissioned: number;
  classes: Record<TrafficClass, number>;
  percent: Record<TrafficClass, number>;
  health: Record<string, number>;
}

export interface Scorecard {
  generated_at: string;
  totals: Totals;
  account_attribute_keys: string[];
  owner_attribute_keys: string[];
  rows: ScoreRow[];
}

export interface AttributeDefinition {
  id: string;
  entity: 'account' | 'user';
  key: string;
  label: string;
  type: 'string' | 'enum';
  enum_values: string[];
  source: 'admin' | 'scim';
}

export const CLASS_LABEL: Record<TrafficClass, string> = {
  green: 'Managed',
  yellow: 'Vaulted',
  red: 'Listed, not controlled',
};

export const HEALTH_LABEL: Record<string, string> = {
  healthy: 'Healthy',
  pending_first_rotation: 'Pending first rotation',
  overdue: 'Overdue',
  rotation_failed: 'Rotation failed',
  auth_failed: 'Authentication failed',
  quarantined: 'Quarantined',
  needs_enrollment: 'Needs enrollment',
  checkout_open: 'Checkout open',
};

// useJSON loads a GET route and exposes reload; errors are shown, never swallowed.
export function useJSON<T>(url: string | null): { data: T | null; error: string; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState('');
  const [tick, setTick] = useState(0);
  const shown = useRef<string | null>(null);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    // Never show another query's rows as the current ones (exports follow the URL); a reload
    // of the same URL keeps them until the answer arrives.
    if (shown.current !== url) setData(null);
    shown.current = url;
    if (!url) return;
    let live = true;
    fetch(url)
      .then(async (r) => {
        if (!r.ok) throw new Error(await errorText(r));
        return r.json();
      })
      .then((j) => { if (live) { setData(j); setError(''); } })
      .catch((e: Error) => { if (live) { setData(null); setError(e.message); } });
    return () => { live = false; };
  }, [url, tick]);
  return { data, error, reload };
}

export async function errorText(r: Response): Promise<string> {
  try {
    const j = await r.json();
    return j.code ? `${j.error} (${j.code})` : j.error || `HTTP ${r.status}`;
  } catch {
    return `HTTP ${r.status}`;
  }
}

// send writes JSON with the CSRF header and returns the server's refusal text, or ''.
export async function send(method: string, url: string, body?: unknown): Promise<string> {
  try {
    const r = await secureFetch(url, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return r.ok ? '' : errorText(r);
  } catch {
    return 'Could not reach the server; nothing was saved.';
  }
}

// The filter is a query string; dashboard, table and exports share it (spec §8.3).
export function scorecardURL(filter: Record<string, string>, format?: 'csv' | 'json'): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(filter)) if (v) q.set(k, v);
  if (format) q.set('format', format);
  const s = q.toString();
  return '/api/reports/scorecard' + (s ? '?' + s : '');
}

// localInput formats d for a datetime-local input in the browser's own time zone.
export function localInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
