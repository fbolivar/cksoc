/** API de Persistencia de Identidad (M365). */
import { api } from './api';

export type Sev = 'critica' | 'alta' | 'media' | 'baja';
export interface IdpFinding { tipo: string; tipoLabel: string; user: string; actor: string; ip: string | null; detalle: string; ts: string; sev: Sev }
export interface IdpOverview { generatedAt: string; range: string; kpis: { mfa: number; delegacion: number; caPolicy: number; tokenReset: number }; hallazgos: IdpFinding[] }

export const idpersistApi = {
  get: (days = '30d') => api.get<IdpOverview>('/idpersist', { params: { days } }).then((r) => r.data),
  refresh: () => api.post<{ ok: boolean; nuevos: number }>('/idpersist/refresh', {}, { timeout: 60_000 }).then((r) => r.data),
};
