/** Tipos y API de File Integrity Monitoring (FIM). */
import { api } from './api';

export type FimCriticality = 'critica' | 'media' | 'baja';

export interface FimChange {
  path: string;
  event: string;
  mode: string;
  user: string;
  agent: string;
  level: number;
  sha256: string;
  timestamp: string;
  criticality: FimCriticality;
}

export interface FimData {
  resumen: { total: number; added: number; modified: number; deleted: number; agentes: number; criticos: number; signalOnly: boolean };
  porAgente: { agent: string; count: number }[];
  topPaths: { path: string; count: number; criticality: FimCriticality }[];
  recientes: FimChange[];
}

export const CRIT_META: Record<FimCriticality, { label: string; color: string }> = {
  critica: { label: 'Crítica', color: '#ef4444' },
  media: { label: 'Media', color: '#f59e0b' },
  baja: { label: 'Baja', color: '#94a3b8' },
};

export const fimApi = {
  get: (hours: number, signalOnly = true) =>
    api.get<FimData>('/fim', { params: { hours, signal: signalOnly ? 1 : 0 } }).then((r) => r.data),
};

export const EVENT_META: Record<string, { color: string; label: string }> = {
  added: { color: '#22c55e', label: 'Añadido' },
  modified: { color: '#eab308', label: 'Modificado' },
  deleted: { color: '#ef4444', label: 'Eliminado' },
};
