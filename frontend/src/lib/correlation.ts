/** Correlación multi-fuente: casos agrupados por IP de origen. */
import { api } from './api';

export interface Correlation {
  srcip: string;
  external: boolean;
  count: number;
  maxLevel: number;
  band: 'baja' | 'media' | 'alta' | 'critica';
  distinctRules: number;
  agents: string[];
  fortiCount: number;
  wazuhCount: number;
  crossSource: boolean;
  firstSeen: string;
  lastSeen: string;
  sampleRule: string;
  mitre: string[];
  iocSource: string | null;
  score: number;
}

export const correlationApi = {
  list: (range: string) =>
    api.get<{ range: string; correlations: Correlation[] }>('/correlation', { params: { range } }).then((r) => r.data.correlations),
};
