/** Tipos y llamadas del panel de Remediación (winget vía Velociraptor). */
import { api } from './api';

export interface RemediationHost {
  host: string;
  os: string | null;
  online: boolean;
  lastSeenH: number | null;
  isPilot: boolean;
}

export interface WingetPackage {
  name: string;
  id: string;
  current: string;
  available: string;
  source: string;
}

export interface RemediationJob {
  id: string;
  host: string;
  client_id: string;
  flow_id: string | null;
  kind: 'scan' | 'apply';
  package: string | null;
  status: 'running' | 'done' | 'error';
  exit_code: number | null;
  packages: WingetPackage[] | null;
  output: string | null;
  error: string | null;
  actor_email: string | null;
  created_at: string;
  finished_at: string | null;
}

export const remediationApi = {
  hosts: () =>
    api.get<{ hosts: RemediationHost[]; pilotHosts: string[] }>('/remediation/hosts').then((r) => r.data),
  scan: (host: string) =>
    api.post<{ job: RemediationJob }>('/remediation/scan', { host }).then((r) => r.data.job),
  apply: (host: string, packageId: string) =>
    api.post<{ job: RemediationJob }>('/remediation/apply', { host, packageId, confirm: true }).then((r) => r.data.job),
  job: (id: string) =>
    api.get<{ job: RemediationJob }>(`/remediation/job/${id}`).then((r) => r.data.job),
  jobs: () =>
    api.get<{ jobs: RemediationJob[] }>('/remediation/jobs').then((r) => r.data.jobs),
};

/** Sondea un job hasta que deja de estar 'running' (o hasta agotar los intentos). */
export async function pollJob(id: string, onTick?: (j: RemediationJob) => void, tries = 200, everyMs = 5000): Promise<RemediationJob> {
  let last: RemediationJob | null = null;
  for (let i = 0; i < tries; i++) {
    last = await remediationApi.job(id);
    onTick?.(last);
    if (last.status !== 'running') return last;
    await new Promise((r) => setTimeout(r, everyMs));
  }
  return last as RemediationJob;
}
