/** API del módulo Observabilidad (tendencia de recursos de la infraestructura del SOC). */
import { api } from './api';

export type Timeframe = 'hour' | 'day' | 'week' | 'month' | 'year';

export interface ResPoint {
  t: number; cpu: number | null; mem: number | null; disk: number | null;
  load: number | null; iowait: number | null; netin: number | null; netout: number | null; swap: number | null;
}
export interface InvEntity {
  kind: 'node' | 'vm'; id: string; vmid?: number; label: string; rol: string;
  status: string; cpu: number | null; mem: number | null; maxmemGB: number | null; uptimeS: number | null;
}
export interface Inventory { ok: boolean; entidades: InvEntity[]; error?: string }
export interface NodeTrend { ok: boolean; node: string; puntos: ResPoint[]; error?: string }
export interface VmTrend { ok: boolean; vmid: number; puntos: ResPoint[]; error?: string }

export const obsApi = {
  inventory: () => api.get<Inventory>('/obs/inventory').then((r) => r.data),
  node: (timeframe: Timeframe = 'day') => api.get<NodeTrend>('/obs/node', { params: { timeframe } }).then((r) => r.data),
  vm: (vmid: number, timeframe: Timeframe = 'day') => api.get<VmTrend>(`/obs/vm/${vmid}`, { params: { timeframe } }).then((r) => r.data),
};
