/** API del Dark Web Radar (centro de fugas). */
import { api } from './api';

export type Sev = 'critica' | 'alta' | 'media' | 'baja';
export interface DwFinding { source: string; severity: Sev; title: string; detail: string; url: string | null; date: string | null }
export interface DwSource { key: string; label: string; estado: 'activo' | 'requiere_config' | 'requiere_feed'; nota: string }
export interface DwRadar {
  generatedAt: string;
  kpis: { total: number; credenciales: number; ransomware: number; github: number };
  fuentes: DwSource[];
  hallazgos: DwFinding[];
}

export const darkwebApi = {
  get: () => api.get<DwRadar>('/darkweb').then((r) => r.data),
  refresh: () => api.post<DwRadar>('/darkweb/refresh', {}, { timeout: 60_000 }).then((r) => r.data),
};
