/** API del módulo Inteligencia de Ransomware. */
import { api } from './api';

export type Relevance = 'directo' | 'pais' | 'sector' | null;
export interface RwVictim {
  victim: string; group: string; country: string | null; sector: string | null;
  discovered: string | null; published: string | null; domain: string | null; url: string | null;
  description: string | null; relevance: Relevance; relWhy: string | null;
}
export interface RwOverview {
  generatedAt: string; configured: boolean; pais: string; watchActivo: boolean;
  kpis: { recientes: number; gruposActivos: number; victimasPais: number; sectorHits: number; directos: number };
  relevantes: RwVictim[]; recientes: RwVictim[]; topGrupos: { group: string; count: number }[];
}

export const ransomwareApi = {
  overview: (days = 30) => api.get<RwOverview>('/ransomware', { params: { days } }).then((r) => r.data),
  refresh: () => api.post<{ ok: boolean; nuevos: number }>('/ransomware/refresh', {}, { timeout: 60_000 }).then((r) => r.data),
};
