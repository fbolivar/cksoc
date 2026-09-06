/** Cliente del Centro de Acción (cola unificada + despachador). */
import { api } from './api';

export type Severity = 'alta' | 'media' | 'baja';
export interface ActionButton { kind: string; label: string; danger?: boolean; link?: string; params: Record<string, string> }
export interface ActionItem {
  key: string;
  source: string;
  severity: Severity;
  title: string;
  subject: string;
  reason: string;
  meta: { label: string; value: string }[];
  actions: ActionButton[];
}
export interface ActionQueue {
  generatedAt: string;
  total: number;
  bySeverity: Record<Severity, number>;
  items: ActionItem[];
}

export const actionCenterApi = {
  queue: () => api.get<ActionQueue>('/action-center').then((r) => r.data),
  execute: (kind: string, params: Record<string, string>) =>
    api.post<{ ok: boolean; kind: string; result: unknown }>('/action-center/execute', { kind, params }).then((r) => r.data),
};
