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

export type AssetCategory = 'ep' | 'srv' | 'net';
export type RiskBand = 'critico' | 'alto' | 'medio' | 'monitoreado' | 'sano';
export interface RadarAsset {
  name: string;
  category: AssetCategory;
  risk: number;
  band: RiskBand;
  criticalVulns: number;
  highVulns: number;
  alerts24h: number;
  critAlerts: number;
  maxLevel: number;
  status: string;
  os: string;
  ip: string;
}
export interface AssetRadar { total: number; assets: RadarAsset[]; generatedAt: string }

export interface SedeMetrics {
  name: string;
  region: string;
  rol?: string;
  agentes: number;
  agentesActivos: number;
  logins7d: number;
  usuarios: number;
  users: string[];
  agentNames: string[];
  ultimaActividad: string | null;
  estado: 'activa' | 'inactiva';
}

export interface Pulse {
  sistema: 'OPERATIVO' | 'EN GESTIÓN' | 'ATENCIÓN';
  ingestaMin: number;
  discoPct: number | null;
  kevEnv: number;
  alertas24h: number;
  deltaPct: number;
}
export interface AlertTrend { range: string; critica: number[]; alta: number[]; media: number[] }

export const overviewApi = {
  get: () => api.get<OverviewData>('/overview').then((r) => r.data),
  radar: () => api.get<AssetRadar>('/overview/radar').then((r) => r.data),
  sedes: () => api.get<{ sedes: SedeMetrics[] }>('/overview/sedes').then((r) => r.data.sedes),
  trend: (range: string) => api.get<AlertTrend>('/overview/trend', { params: { range } }).then((r) => r.data),
  pulse: () => api.get<Pulse>('/overview/pulse').then((r) => r.data),
};

export const SEMAFORO_META = {
  verde: { color: '#22c55e', label: 'Operación normal' },
  amarillo: { color: '#eab308', label: 'Bajo gestión' },
  rojo: { color: '#ef4444', label: 'Requiere atención' },
};
