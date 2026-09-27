/** API del módulo DRP (riesgo digital: typosquatting + CT + credenciales). */
import { api } from './api';

export type DrpSev = 'critica' | 'alta' | 'media';
export interface DrpFinding {
  id: string; tipo: string; brand: string; dominio: string;
  severidad: DrpSev; detalle: string; meta: Record<string, unknown>;
  estado: string; primera_vez: string; ultima_vez: string;
}
export interface DrpOverview {
  severidad: Record<DrpSev, number>;
  tipo: Record<string, number>;
  conMx: number;
  credencialesExpuestas: number;
  top: DrpFinding[];
  lastScan: string | null;
}
export interface DrpScanResult { brands: number; generados: number; registrados: number; certs: number; nuevos: number }

export const drpApi = {
  overview: () => api.get<DrpOverview>('/drp/overview').then((r) => r.data),
  findings: (f: { estado?: string; tipo?: string } = {}) =>
    api.get<{ findings: DrpFinding[] }>('/drp/findings', { params: f }).then((r) => r.data.findings),
  scan: () => api.post<DrpScanResult>('/drp/scan').then((r) => r.data),
  setStatus: (id: string, estado: 'open' | 'resolved' | 'dismissed') =>
    api.put(`/drp/findings/${id}/status`, { estado }).then((r) => r.data),
};
