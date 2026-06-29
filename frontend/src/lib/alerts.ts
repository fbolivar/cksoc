/** Tipos y API del Explorador de Alertas. */
import { api } from './api';

export type Band = 'baja' | 'media' | 'alta' | 'critica';

export interface AlertHit {
  id: string;
  index: string;
  timestamp: string;
  ruleId: string;
  level: number;
  band: Band;
  description: string;
  agent: string;
  srcip: string | null;
  mitre: string[];
  groups: string[];
}

export interface AlertSearchResult {
  total: number;
  capped: boolean;
  items: AlertHit[];
}

export interface AlertFilters {
  range: string;
  band?: string;
  agent?: string;
  srcip?: string;
  ruleId?: string;
  q?: string;
  mitre?: string;
  page: number;
  size: number;
}

export const alertsApi = {
  search: (f: AlertFilters) =>
    api.get<AlertSearchResult>('/wazuh/alerts/search', { params: f }).then((r) => r.data),
  detail: (index: string, id: string) =>
    api.get<{ source: Record<string, unknown> }>('/wazuh/alerts/detail', { params: { index, id } }).then((r) => r.data.source),
};

export const BAND_COLOR: Record<Band, string> = {
  baja: '#22c55e',
  media: '#eab308',
  alta: '#f97316',
  critica: '#ef4444',
};
export const BAND_LABEL: Record<Band, string> = {
  baja: 'Baja',
  media: 'Media',
  alta: 'Alta',
  critica: 'Crítica',
};
