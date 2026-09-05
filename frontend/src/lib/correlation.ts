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
  // externalOnly (por defecto true): solo IPs externas (atacantes). false = incluye internas.
  list: (range: string, externalOnly = true) =>
    api.get<{ range: string; correlations: Correlation[] }>('/correlation', { params: { range, internal: externalOnly ? undefined : 1 } }).then((r) => r.data.correlations),
};
