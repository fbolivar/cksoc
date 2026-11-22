/** API de Riesgo de Datos en Nube (M365). */
import { api } from './api';

export type Sev = 'critica' | 'alta' | 'media';
export interface CdFinding { tipo: string; tipoLabel: string; user: string; count: number; umbral: number; sev: Sev }
export interface CdOverview {
  generatedAt: string; range: string;
  umbrales: { del: number; mod: number; dl: number; share: number; anon: number };
  kpis: { borrado: number; modificacion: number; descarga: number; comparticion: number; anonimo: number };
  hallazgos: CdFinding[];
}

export const cloudDataApi = {
  get: (days = '24h') => api.get<CdOverview>('/clouddata', { params: { days } }).then((r) => r.data),
  refresh: () => api.post<{ ok: boolean; nuevos: number }>('/clouddata/refresh', {}, { timeout: 60_000 }).then((r) => r.data),
};
