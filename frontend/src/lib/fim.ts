/** Tipos y API de File Integrity Monitoring (FIM). */
import { api } from './api';

export interface FimChange {
  path: string;
  event: string;
  mode: string;
  user: string;
  agent: string;
  level: number;
  sha256: string;
  timestamp: string;
}

export interface FimData {
  resumen: { total: number; added: number; modified: number; deleted: number; agentes: number };
  porAgente: { agent: string; count: number }[];
  topPaths: { path: string; count: number }[];
  recientes: FimChange[];
}

export const fimApi = {
  get: (hours: number) => api.get<FimData>('/fim', { params: { hours } }).then((r) => r.data),
};

export const EVENT_META: Record<string, { color: string; label: string }> = {
  added: { color: '#22c55e', label: 'Añadido' },
  modified: { color: '#eab308', label: 'Modificado' },
  deleted: { color: '#ef4444', label: 'Eliminado' },
};
