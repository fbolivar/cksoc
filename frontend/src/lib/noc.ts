/** API del módulo NOC (disponibilidad). */
import { api } from './api';

export type CheckKind = 'icmp' | 'tcp' | 'http';
export type NocStatus = 'up' | 'down' | 'unknown';
export interface NocUptime { d1: number | null; d7: number | null; d30: number | null }
export interface NocTarget {
  id: string; name: string; host: string; kind: CheckKind; port: number | null; path: string | null;
  grupo: string; enabled: boolean; status: NocStatus; latency_ms: number | null;
  last_check: string | null; last_change: string | null; since: string | null; fail_count: number;
  snmp_enabled: boolean;
  sys_descr: string | null; uptime_s: number | null; cpu_pct: number | null; mem_pct: number | null;
  if_up: number | null; if_total: number | null; temp_c: number | null; snmp_at: string | null;
  uptime?: NocUptime;
}
export interface NocOverview {
  kpis: { total: number; up: number; down: number; disabled: number; avgLatency: number | null; avgUptime30: number | null };
  grupos: { grupo: string; esCliente: boolean; targets: NocTarget[] }[];
  eventos: { name: string; status: NocStatus; latency_ms: number | null; at: string }[];
  lastRun: string | null;
}
export interface NocReport {
  dias: number;
  objetivos: { name: string; host: string; grupo: string; esCliente: boolean; status: NocStatus; uptimePct: number; caidas: number; downMin: number }[];
}
export interface NocTrend { dias: number; puntos: { dia: string; caidas: number; equipos: number }[] }
export interface NocAgent { id: string; name: string; ip: string; status: string; health: string; kind: string; needsAttention: boolean; staleDays: number | null }
export interface NocAgents { ok: boolean; summary: { total: number; active: number; disconnected: number; neverConnected: number; pending: number } | null; agents: NocAgent[] }

export const nocApi = {
  overview: () => api.get<NocOverview>('/noc/overview').then((r) => r.data),
  report: (days = 30) => api.get<NocReport>('/noc/report', { params: { days } }).then((r) => r.data),
  trend: (days = 14) => api.get<NocTrend>('/noc/trend', { params: { days } }).then((r) => r.data),
  agents: () => api.get<NocAgents>('/noc/agents').then((r) => r.data),
  add: (t: { name: string; host: string; kind: CheckKind; port?: number | null; path?: string | null; grupo?: string; snmpEnabled?: boolean; snmpCommunity?: string }) =>
    api.post<{ id: string }>('/noc/targets', t).then((r) => r.data),
  toggle: (id: string, enabled: boolean) => api.put(`/noc/targets/${id}`, { enabled }).then((r) => r.data),
  setSnmp: (id: string, enabled: boolean, community?: string) => api.put(`/noc/targets/${id}/snmp`, { enabled, community }).then((r) => r.data),
  remove: (id: string) => api.delete(`/noc/targets/${id}`).then((r) => r.data),
  checkNow: () => api.post('/noc/check', {}, { timeout: 60_000 }).then((r) => r.data),
};
