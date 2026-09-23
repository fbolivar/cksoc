/** UEBA: analítica de comportamiento de usuarios (anomalías de login). */
import { api } from './api';

export type Detector = 'new_host' | 'off_hours' | 'auth_failure_spike' | 'impossible_travel' | 'new_country';
export type Severity = 'baja' | 'media' | 'alta' | 'critica';

export interface Anomaly {
  id: string;
  detector: Detector;
  entity: string;
  entity_type: string;
  severity: Severity;
  score: number;
  title: string;
  summary: string;
  evidence: Record<string, unknown>;
  source: string;
  status: 'open' | 'ack' | 'dismissed';
  first_seen: string;
  last_seen: string;
  ack_by: string | null;
  ack_at: string | null;
}

export interface UebaSettings {
  biz_start_hour: number;
  biz_end_hour: number;
  include_weekend: boolean;
  lookback_days: number;
  recent_hours: number;
  fail_threshold: number;
  impossible_kmh: number;
}

export interface EntityProfile {
  user: string;
  baseline: { hosts: string[]; countries: string[]; total: number; offRatio: number } | null;
  anomalies: Anomaly[];
}

export interface MonitoredEntity {
  user: string;
  logins: number;
  fails: number;
  hosts: string[];
  lastSeen: string;
  countries: string[];
  srcips: string[];
}

export const DETECTOR_ES: Record<Detector, string> = {
  new_host: 'Host nuevo',
  off_hours: 'Fuera de horario',
  auth_failure_spike: 'Pico de fallos',
  impossible_travel: 'Viaje imposible',
  new_country: 'País nuevo',
};

export const uebaApi = {
  anomalies: (params: { status?: string; detector?: string; days?: number } = {}) =>
    api.get<{ open: number; anomalies: Anomaly[] }>('/ueba/anomalies', { params }).then((r) => r.data),
  entity: (user: string) => api.get<EntityProfile>(`/ueba/entity/${encodeURIComponent(user)}`).then((r) => r.data),
  decide: (id: string, decision: 'ack' | 'dismiss' | 'reopen') =>
    api.post<Anomaly>(`/ueba/anomalies/${id}/${decision}`).then((r) => r.data),
  settings: () => api.get<UebaSettings>('/ueba/settings').then((r) => r.data),
  updateSettings: (body: Partial<UebaSettings>) => api.put<UebaSettings>('/ueba/settings', body).then((r) => r.data),
  entities: () => api.get<{ entities: MonitoredEntity[] }>('/ueba/entities').then((r) => r.data),
  scan: () => api.post<{ logins: number; users: number; anomalies: number; byDetector: Record<string, number> }>('/ueba/scan').then((r) => r.data),
};
