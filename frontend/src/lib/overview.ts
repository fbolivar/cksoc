/** Tipos y API del Resumen Ejecutivo consolidado. */
import { api } from './api';

export interface OverviewData {
  generadoEn: string;
  global: { semaforo: 'verde' | 'amarillo' | 'rojo'; motivo: string };
  amenazas: { alertas24h: number; criticas24h: number; altasCriticas24h: number; ataquesExternos: number };
  endpoints: { vulnCriticas: number; vulnAltas: number; vulnTotal: number; hardeningScore: number; fimCambios: number };
  cumplimiento: { marco: string; controles: number }[];
  siem: { semaforo: 'verde' | 'amarillo' | 'rojo'; ok: number; total: number };
  agentes: { activos: number; total: number };
}

export const overviewApi = {
  get: () => api.get<OverviewData>('/overview').then((r) => r.data),
};

export const SEMAFORO_META = {
  verde: { color: '#22c55e', label: 'Operación normal' },
  amarillo: { color: '#eab308', label: 'Bajo gestión' },
  rojo: { color: '#ef4444', label: 'Requiere atención' },
};
