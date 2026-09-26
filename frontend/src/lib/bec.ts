/** API del módulo anti-BEC (señales de compromiso de correo). */
import { api } from './api';

export type BecSev = 'critica' | 'alta' | 'media';
export interface BecFinding {
  id: string; tipo: string; usuario: string; ref: string;
  severidad: BecSev; detalle: string; meta: Record<string, unknown>;
  estado: string; primera_vez: string; ultima_vez: string;
}
export interface BecOverview {
  severidad: Record<BecSev, number>;
  tipo: Record<string, number>;
  top: BecFinding[];
  lastScan: string | null;
}
export interface BecScanResult { window: string; reglas: number; correoRevisado: number; nuevos: number }

export const becApi = {
  overview: () => api.get<BecOverview>('/bec/overview').then((r) => r.data),
  findings: (f: { estado?: string; tipo?: string } = {}) =>
    api.get<{ findings: BecFinding[] }>('/bec/findings', { params: f }).then((r) => r.data.findings),
  scan: (range = '7d') => api.post<BecScanResult>('/bec/scan', { range }).then((r) => r.data),
  setStatus: (id: string, estado: 'open' | 'resolved' | 'dismissed') =>
    api.put(`/bec/findings/${id}/status`, { estado }).then((r) => r.data),
};
