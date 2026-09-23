/** Cliente SOAR / Playbooks. */
import { api } from './api';

export type Mode = 'simulacion' | 'activo';
export type ActionType = 'block_ip' | 'create_incident' | 'notify';

export interface PlaybookConditions {
  minLevel?: number; ruleIds?: string[]; mitre?: string[]; agents?: string[]; groups?: string[];
}
export interface Playbook {
  id: string; name: string; description: string | null; enabled: boolean; mode: Mode;
  conditions: PlaybookConditions; actions: { type: ActionType }[]; cooldownMin: number;
  createdBy: string | null; createdAt: string; updatedAt: string;
}
export interface PlaybookRun {
  id: string; playbook_id: string; playbook_name: string; target: string;
  matched: { level: number; ruleId: string; ip: string | null; agent: string; description: string };
  actions: { type: string; status: string; detail?: string }[];
  mode: Mode; created_at: string;
}

export interface PlaybookInput {
  name: string; description?: string; mode?: Mode; enabled?: boolean;
  conditions: PlaybookConditions; actions: { type: ActionType }[]; cooldownMin?: number;
}

export const ACTION_LABELS: Record<ActionType, string> = {
  block_ip: 'Bloquear IP (SonicWall)',
  create_incident: 'Crear incidente',
  notify: 'Notificar (in-app)',
};

export const playbooksApi = {
  list: () => api.get<{ playbooks: Playbook[] }>('/playbooks').then((r) => r.data.playbooks),
  create: (p: PlaybookInput) => api.post<Playbook>('/playbooks', p).then((r) => r.data),
  update: (id: string, p: Partial<PlaybookInput>) => api.put<Playbook>(`/playbooks/${id}`, p).then((r) => r.data),
  remove: (id: string) => api.delete(`/playbooks/${id}`).then((r) => r.data),
  test: (id: string, sample?: Record<string, unknown>) =>
    api.post<{ matched: boolean; results: { type: string; status: string; detail?: string }[] }>(`/playbooks/${id}/test`, sample ?? {}).then((r) => r.data),
  runs: () => api.get<{ runs: PlaybookRun[] }>('/playbooks/runs').then((r) => r.data.runs),
};
