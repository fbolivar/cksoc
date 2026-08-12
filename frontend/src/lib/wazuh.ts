/** Tipos y llamadas a la API de Wazuh (vista del frontend). */
import { api } from './api';

export type TimeRange = '24h' | '7d' | '30d';

export interface SeverityBands {
  baja: number;
  media: number;
  alta: number;
  critica: number;
}

export interface AlertsSummary {
  total: number;
  byLevel: { level: number; count: number }[];
  byBand: SeverityBands;
}

export interface TimelinePoint {
  ts: string;
  count: number;
}

export interface AgentsSummary {
  total: number;
  active: number;
  disconnected: number;
  neverConnected: number;
  pending: number;
}

export interface AgentItem {
  id: string;
  name: string;
  ip: string;
  status: string;
  os: string;
  version: string;
  lastKeepAlive: string;
}

export interface SedeBucket {
  sede: string;
  total: number;
  active: number;
}

/** Intervalo de date_histogram apropiado para cada rango. */
export function intervalFor(range: TimeRange): string {
  switch (range) {
    case '24h':
      return '1h';
    case '7d':
      return '3h';
    case '30d':
      return '1d';
  }
}

export const wazuhApi = {
  summary: (range: TimeRange) =>
    api.get<AlertsSummary>('/wazuh/alerts/summary', { params: { range } }).then((r) => r.data),

  timeline: (range: TimeRange, interval: string) =>
    api
      .get<{ data: TimelinePoint[] }>('/wazuh/alerts/timeline', { params: { range, interval } })
      .then((r) => r.data.data),

  topAgents: (range: TimeRange, size = 8) =>
    api
      .get<{ data: { agent: string; count: number }[] }>('/wazuh/alerts/top-agents', {
        params: { range, size },
      })
      .then((r) => r.data.data),

  mitre: (range: TimeRange, size = 8) =>
    api
      .get<{ data: { technique: string; count: number }[] }>('/wazuh/alerts/mitre', {
        params: { range, size },
      })
      .then((r) => r.data.data),

  agentsSummary: () =>
    api.get<AgentsSummary>('/wazuh/agents/summary').then((r) => r.data),

  agents: (limit = 50) =>
    api.get<{ data: AgentItem[] }>('/wazuh/agents', { params: { limit } }).then((r) => r.data.data),

  agentsBySede: () =>
    api.get<{ data: SedeBucket[] }>('/wazuh/agents/by-sede').then((r) => r.data.data),
};
