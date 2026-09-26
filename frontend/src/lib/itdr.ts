/** API del módulo ITDR (amenazas de identidad sobre logins O365). */
import { api } from './api';

export type ItdrSev = 'critica' | 'alta' | 'media';
export interface ItdrFinding {
  id: string; usuario: string; tipo: string; ref: string;
  severidad: ItdrSev; detalle: string; meta: Record<string, unknown>;
  estado: string; primera_vez: string; ultima_vez: string;
}
export interface ItdrOverview {
  severidad: Record<ItdrSev, number>;
  tipo: Record<string, number>;
  top: ItdrFinding[];
  lastScan: string | null;
}
export interface ItdrScanResult { window: string; viajeImposible: number; mfaFatigue: number; nuevos: number }

export const itdrApi = {
  overview: () => api.get<ItdrOverview>('/itdr/overview').then((r) => r.data),
  findings: (f: { estado?: string; tipo?: string } = {}) =>
    api.get<{ findings: ItdrFinding[] }>('/itdr/findings', { params: f }).then((r) => r.data.findings),
  scan: (range = '24h') => api.post<ItdrScanResult>('/itdr/scan', { range }).then((r) => r.data),
  setStatus: (id: string, estado: 'open' | 'resolved' | 'dismissed') =>
    api.put(`/itdr/findings/${id}/status`, { estado }).then((r) => r.data),
};
