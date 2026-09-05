/** Tipos y llamadas del modulo de respuesta semi-automatica. */
import { api } from './api';

export interface Reputation {
  abuseScore: number;
  totalReports: number;
  countryCode: string | null;
  isp: string | null;
  domain: string | null;
  lastReportedAt: string | null;
  configured: boolean;
}

export interface Incident {
  ip: string;
  attempts: number;
  severityMax: number;
  lastSeen: string;
  ruleDescription: string;
  country: string;
  city: string;
  lat: number | null;
  lon: number | null;
  reputation: Reputation | null;
  blocked: boolean;
  ioc: boolean;
  attack: boolean;
  threat: boolean;
  whitelisted: boolean;
  threatScore: number;
}

export interface ResponseStatus {
  configured: boolean;
  connection: { ok: boolean; group?: string; count?: number; error?: string };
  whitelist: string[];
  adminIp: string;
}

export interface BlockedItem {
  ip: string;
  motivo: string | null;
  usuario_email: string | null;
  blocked_at: string | null;
}

export interface AuditRow {
  id: string;
  ip: string;
  accion: 'block' | 'unblock';
  motivo: string | null;
  usuario_email: string | null;
  resultado: 'success' | 'failed' | 'rejected';
  detalle: string | null;
  alerta_origen_id: string | null;
  created_at: string;
}

export const responseApi = {
  status: () => api.get<ResponseStatus>('/response/status').then((r) => r.data),
  incidents: (hours: number, threatsOnly = true) =>
    api.get<{ incidents: Incident[] }>('/response/incidents', { params: { hours, threats: threatsOnly ? 1 : 0 } }).then((r) => r.data.incidents),
  blocked: () => api.get<{ blocked: BlockedItem[] }>('/response/blocked').then((r) => r.data.blocked),
  history: () => api.get<{ history: AuditRow[] }>('/response/history').then((r) => r.data.history),
  block: (ip: string, motivo: string, alertaOrigenId?: string) =>
    api.post('/response/block', { ip, motivo, alertaOrigenId }).then((r) => r.data),
  unblock: (ip: string) => api.post('/response/unblock', { ip }).then((r) => r.data),
};

/** Color del badge de reputacion AbuseIPDB. */
export function abuseColor(score: number): { bg: string; fg: string; label: string } {
  if (score >= 76) return { bg: 'rgba(239,68,68,0.15)', fg: '#f87171', label: 'Crítica' };
  if (score >= 26) return { bg: 'rgba(249,115,22,0.15)', fg: '#fb923c', label: 'Alta' };
  if (score >= 1) return { bg: 'rgba(234,179,8,0.15)', fg: '#facc15', label: 'Sospechosa' };
  return { bg: 'rgba(107,114,128,0.15)', fg: '#9ca3af', label: 'Sin reportes' };
}
