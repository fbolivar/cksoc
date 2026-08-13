/** Threat Intelligence: IOCs, feeds y coincidencias contra alertas. */
import { api } from './api';

export type IocType = 'ip' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';

export interface Ioc {
  id: string;
  ioc_type: IocType;
  value: string;
  source: string;
  description: string | null;
  tags: string[];
  enabled: boolean;
  last_match_at: string | null;
  match_count: number;
  created_at: string;
}

export interface FeedStatus {
  name: string;
  last_run_at: string | null;
  last_count: number;
  last_status: string | null;
}

export interface IocMatch {
  value: string;
  type: 'ip';
  source: string;
  alertCount: number;
  lastSeen: string;
  sampleRule: string;
  agent: string;
}

export const threatIntelApi = {
  summary: () =>
    api.get<{ total: number; byType: Record<string, number>; feeds: FeedStatus[] }>('/threatintel/summary').then((r) => r.data),
  iocs: (params: { type?: string; q?: string } = {}) =>
    api.get<{ iocs: Ioc[] }>('/threatintel/iocs', { params }).then((r) => r.data.iocs),
  addIoc: (body: { type: IocType; value: string; description?: string; tags?: string[] }) =>
    api.post<Ioc>('/threatintel/iocs', body).then((r) => r.data),
  removeIoc: (id: string) => api.delete(`/threatintel/iocs/${id}`).then((r) => r.data),
  refresh: () => api.post<{ results: { name: string; count: number; status: string }[] }>('/threatintel/feeds/refresh').then((r) => r.data.results),
  matches: () => api.get<{ matches: IocMatch[] }>('/threatintel/matches').then((r) => r.data.matches),
};
