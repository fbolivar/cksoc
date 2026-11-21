/** API del módulo NOC (disponibilidad). */
import { api } from './api';

export type CheckKind = 'icmp' | 'tcp' | 'http';
export type NocStatus = 'up' | 'down' | 'unknown';
export interface NocTarget {
  id: string; name: string; host: string; kind: CheckKind; port: number | null; path: string | null;
  grupo: string; enabled: boolean; status: NocStatus; latency_ms: number | null;
  last_check: string | null; last_change: string | null; since: string | null; fail_count: number;
}
export interface NocOverview {
  kpis: { total: number; up: number; down: number; disabled: number; avgLatency: number | null };
  grupos: { grupo: string; targets: NocTarget[] }[];
  eventos: { name: string; status: NocStatus; latency_ms: number | null; at: string }[];
  lastRun: string | null;
}

export const nocApi = {
  overview: () => api.get<NocOverview>('/noc/overview').then((r) => r.data),
  add: (t: { name: string; host: string; kind: CheckKind; port?: number | null; path?: string | null; grupo?: string }) =>
    api.post<{ id: string }>('/noc/targets', t).then((r) => r.data),
  toggle: (id: string, enabled: boolean) => api.put(`/noc/targets/${id}`, { enabled }).then((r) => r.data),
  remove: (id: string) => api.delete(`/noc/targets/${id}`).then((r) => r.data),
  checkNow: () => api.post('/noc/check', {}, { timeout: 60_000 }).then((r) => r.data),
};
