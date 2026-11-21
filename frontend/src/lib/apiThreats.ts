/** Cliente de Amenazas de API — scorecard OWASP API Security Top 10. */
import { api } from './api';

export type Estado = 'detectado' | 'limpio' | 'sin-cobertura';
export type Sev = 'alta' | 'media' | 'baja' | 'info';
export interface ApiCategoria {
  id: string; nombre: string; estado: Estado; severidad: Sev;
  count: number; evidencia: string[]; fuente: string; ruta: string | null; descripcion: string;
}
export interface ApiThreatsReport {
  range: string; generadoEn: string;
  resumen: { detectadas: number; limpias: number; sinCobertura: number };
  categorias: ApiCategoria[];
}

export const apiThreatsApi = {
  get: (range = '24h') => api.get<ApiThreatsReport>('/api-threats', { params: { range } }).then((r) => r.data),
};

export const EST_COLOR: Record<Estado, string> = {
  detectado: '#ef4444', limpio: '#22c55e', 'sin-cobertura': '#64748b',
};
export const EST_LABEL: Record<Estado, string> = {
  detectado: 'Detectado', limpio: 'Limpio', 'sin-cobertura': 'Sin cobertura',
};
export const SEV_COLOR: Record<Sev, string> = {
  alta: '#ef4444', media: '#f59e0b', baja: '#22c55e', info: '#64748b',
};
