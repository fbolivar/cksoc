/** Cliente de Threat Hunting (búsqueda ad-hoc sobre alertas Wazuh). */
import { api } from './api';

export interface HuntHit {
  id: string;
  timestamp: string;
  ruleId: string;
  level: number;
  description: string;
  agent: string;
  srcip: string | null;
  mitre: string[];
}

export interface Bucket { key: string; count: number; label?: string }

export interface HuntResult {
  total: number;
  capped: boolean;
  items: HuntHit[];
  aggs: { rules: Bucket[]; agents: Bucket[]; srcips: Bucket[]; mitre: Bucket[] };
}

export interface HuntQuery {
  range?: string;
  q?: string;
  agent?: string;
  ruleId?: string;
  minLevel?: number;
  srcip?: string;
  mitre?: string;
  size?: number;
  page?: number;
}

export const huntApi = {
  search: (params: HuntQuery) => {
    const clean = Object.fromEntries(Object.entries(params).filter(([, v]) => v !== undefined && v !== '' && v !== 0));
    return api.get<HuntResult>('/hunt', { params: clean, timeout: 30_000 }).then((r) => r.data);
  },
};
