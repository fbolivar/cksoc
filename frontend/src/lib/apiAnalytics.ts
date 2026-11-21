/** Cliente de Analítica de API por endpoint (sobre web-accesslog de Wazuh). */
import { api } from './api';

export type Sev = 'alta' | 'media' | 'baja' | 'info';
export interface ApiEndpointStat {
  endpoint: string; metodos: string[]; hits: number;
  status: Record<string, number>; fuentesIp: number; topIps: string[];
  authFails: number; notFound: number; serverErrors: number; flag: Sev;
}
export interface ApiHallazgo {
  tipo: string; owasp: string; severidad: Sev; titulo: string; detalle: string; evidencia: string[]; externa: boolean;
}
export interface ApiAnalyticsReport {
  range: string; generadoEn: string; cobertura: boolean;
  fuentes: { name: string; eventos: number }[];
  resumen: { eventos: number; endpoints: number; authFails: number; enumeracion: number; serverErrors: number };
  endpoints: ApiEndpointStat[];
  hallazgos: ApiHallazgo[];
}

export const apiAnalyticsApi = {
  get: (range = '24h') => api.get<ApiAnalyticsReport>('/api-analytics', { params: { range } }).then((r) => r.data),
};

export const SEV_COLOR: Record<Sev, string> = { alta: '#ef4444', media: '#f59e0b', baja: '#22c55e', info: '#64748b' };
