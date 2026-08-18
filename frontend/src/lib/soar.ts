/** SOAR: reglas de respuesta automatizada y cola de aprobación. */
import { api } from './api';

export type TriggerType = 'ioc_ip_match' | 'rule_level' | 'rule_id';
export type ActionType = 'block_ip' | 'isolate_host' | 'create_incident' | 'disable_ad_user' | 'disable_m365_user';
export type Mode = 'auto' | 'approval';

export interface AutomationRule {
  id: string;
  name: string;
  enabled: boolean;
  trigger_type: TriggerType;
  trigger_config: { minLevel?: number; group?: string; ruleId?: string };
  action: ActionType;
  mode: Mode;
  dry_run: boolean;
  cooldown_min: number;
  last_triggered_at: string | null;
  trigger_count: number;
  created_at: string;
}

export interface AutomationEvent {
  id: string;
  rule_name: string | null;
  entity: string;
  action: ActionType;
  status: string;
  detail: Record<string, unknown>;
  created_at: string;
  resolved_at: string | null;
}

export const soarApi = {
  rules: () => api.get<{ rules: AutomationRule[] }>('/soar/rules').then((r) => r.data.rules),
  createRule: (body: Partial<AutomationRule>) => api.post<AutomationRule>('/soar/rules', body).then((r) => r.data),
  updateRule: (id: string, body: Partial<AutomationRule>) => api.put<AutomationRule>(`/soar/rules/${id}`, body).then((r) => r.data),
  removeRule: (id: string) => api.delete(`/soar/rules/${id}`).then((r) => r.data),
  events: () => api.get<{ pending: number; events: AutomationEvent[] }>('/soar/events').then((r) => r.data),
  resolve: (id: string, decision: 'approve' | 'reject') => api.post<AutomationEvent>(`/soar/events/${id}/${decision}`).then((r) => r.data),
  run: () => api.post<{ evaluated: number; created: number }>('/soar/run').then((r) => r.data),
};
