/** Cliente de la integración Velociraptor (DFIR). */
import { api } from './api';

export interface VeloClient {
  client_id: string;
  host: string;
  system: string;
  release: string;
  last_seen_at?: number;
}

export interface VeloCollectResult {
  host: string;
  client_id: string;
  flow_id: string;
  url: string;
}

export const velociraptorApi = {
  status: () =>
    api.get<{ available: boolean; clients?: number; error?: string }>('/velociraptor/status').then((r) => r.data),
  clients: () => api.get<{ clients: VeloClient[] }>('/velociraptor/clients').then((r) => r.data.clients),
  collect: (host: string) =>
    api.post<VeloCollectResult>('/velociraptor/collect', { host }).then((r) => r.data),
};
