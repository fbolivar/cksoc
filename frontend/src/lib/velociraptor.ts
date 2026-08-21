/** Cliente de la integración Velociraptor (DFIR). */
import { api } from './api';

export interface VeloClient {
  client_id: string;
  host: string;
  system: string;
  release: string;
  last_seen_at?: number;
  isolated?: boolean;
}

export type EndpointAction = 'isolate' | 'release' | 'triage';

export interface VeloActionResult {
  host: string;
  client_id: string;
  action: EndpointAction;
  flow_id: string;
  url: string;
}

export interface VeloCollectResult {
  host: string;
  client_id: string;
  flow_id: string;
  url: string;
}

export interface VeloFlow {
  flow_id: string;
  artifacts: string;
  state: string; // RUNNING | FINISHED | ERROR
  created: string; // ISO
  rows: number;
  creator: string;
  url: string;
}

export interface VeloArtifact {
  name: string;
  description: string;
}

export interface VeloResultSource {
  artifact: string;
  columns: string[];
  count: number;
  rows: Record<string, unknown>[];
}

export interface VeloRec {
  host: string; ip: string; os: string; category: string;
  risk: number; band: string; status: string;
  severity: 'alta' | 'media'; reason: string; hasVelo: boolean; isolated: boolean;
}

export const velociraptorApi = {
  recommendations: () =>
    api.get<{ available: boolean; items: VeloRec[]; error?: string }>('/velociraptor/recommendations').then((r) => r.data),
  status: () =>
    api.get<{ available: boolean; clients?: number; error?: string }>('/velociraptor/status').then((r) => r.data),
  clients: () => api.get<{ clients: VeloClient[] }>('/velociraptor/clients').then((r) => r.data.clients),
  flows: (clientId: string) =>
    api.get<{ flows: VeloFlow[] }>(`/velociraptor/clients/${clientId}/flows`).then((r) => r.data.flows),
  artifacts: () => api.get<{ artifacts: VeloArtifact[] }>('/velociraptor/artifacts').then((r) => r.data.artifacts),
  flowResults: (clientId: string, flowId: string) =>
    api.get<{ sources: VeloResultSource[] }>(`/velociraptor/clients/${clientId}/flows/${flowId}/results`).then((r) => r.data.sources),
  collect: (host: string, artifact?: string) =>
    api.post<VeloCollectResult>('/velociraptor/collect', { host, artifact }).then((r) => r.data),
  action: (host: string, action: EndpointAction) =>
    api.post<VeloActionResult>('/velociraptor/action', { host, action }).then((r) => r.data),
};
