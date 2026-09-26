/** API del módulo XDR (grafo de actividad cross-dominio / SmartGrouping). */
import { api } from './api';

export type EntType = 'ip' | 'host' | 'user' | 'domain';

export interface ActivityGroup {
  id: string; alertas: number; reglas: number; maxLevel: number;
  desde: string; hasta: string;
  entidades: { type: EntType; label: string; ioc: boolean }[];
  tipos: EntType[];
  topReglas: { desc: string; count: number }[];
}
export interface GraphNode { id: string; type: EntType; label: string; alertas: number; maxLevel: number; ioc: boolean; seed: boolean }
export interface GraphEdge { from: string; to: string; weight: number }
export interface TimelineItem { ts: string; rule: string; level: number; entidades: string[] }
export interface ActivityGraph {
  seed: { type: EntType; value: string };
  nodes: GraphNode[]; edges: GraphEdge[]; timeline: TimelineItem[];
  stats: { alertas: number; byType: Record<string, number> };
}

export const xdrApi = {
  groups: (range = '24h') => api.get<{ groups: ActivityGroup[] }>('/xdr/groups', { params: { range } }).then((r) => r.data.groups),
  graph: (type: EntType, value: string, range = '7d') =>
    api.get<ActivityGraph>('/xdr/graph', { params: { type, value, range } }).then((r) => r.data),
};
