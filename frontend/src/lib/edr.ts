/** API del módulo EDR/NGAV (conector on-demand a Defender/SentinelOne). */
import { api } from './api';

export type EdrSev = 'critica' | 'alta' | 'media' | 'baja' | 'info';
export interface EdrStatus { provider: 'sentinelone' | 'defender' | 'none'; configured: boolean; reachable: boolean; error: string | null }
export interface EdrAlert { id: string; title: string; severity: EdrSev; category: string; device: string; user: string | null; status: string; createdAt: string }
export interface EdrDevice { id: string; name: string; os: string; health: string; isolated: boolean; riskLevel: string; lastSeen: string }
export interface EdrOverview {
  status: EdrStatus; alerts: EdrAlert[]; devices: EdrDevice[];
  kpis: { alertas: number; criticas: number; dispositivos: number; aislados: number; enRiesgo: number };
}

export const edrApi = {
  overview: () => api.get<EdrOverview>('/edr/overview').then((r) => r.data),
  status: () => api.get<EdrStatus>('/edr/status').then((r) => r.data),
  isolate: (id: string) => api.post(`/edr/devices/${encodeURIComponent(id)}/isolate`).then((r) => r.data),
  unisolate: (id: string) => api.post(`/edr/devices/${encodeURIComponent(id)}/unisolate`).then((r) => r.data),
  scan: (id: string) => api.post(`/edr/devices/${encodeURIComponent(id)}/scan`).then((r) => r.data),
};
