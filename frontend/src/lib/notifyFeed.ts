/** Feed de notificaciones para la campanita (reusa /api/notifications/log). */
import { api } from './api';

export interface FeedItem {
  id: string;
  title: string;
  status: 'sent' | 'failed' | 'skipped' | string;
  createdAt: string;
  link: string;
  live?: boolean;
}

interface LogRow {
  id: string;
  tipo?: string | null;
  rule_name: string | null;
  origen?: string | null;
  alert_rule_id?: string | null;
  status: string;
  created_at: string;
}

const IP_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/** Construye el destino de la notificación segun su origen/tipo. */
export function linkFor(opts: { origen?: string | null; ruleId?: string | null }): string {
  const { origen, ruleId } = opts;
  if (origen === 'threat-hunting') return '/hunting';
  const params = new URLSearchParams();
  if (origen && IP_RE.test(origen)) params.set('srcip', origen);
  else if (origen && origen !== 'desconocido') params.set('agent', origen);
  if (ruleId) params.set('ruleId', ruleId);
  const qs = params.toString();
  return qs ? `/alertas?${qs}` : '/alertas';
}

export async function fetchFeed(): Promise<FeedItem[]> {
  const { data } = await api.get<{ log: LogRow[] }>('/notifications/log');
  return (data.log ?? []).map((r) => ({
    id: r.id,
    title: r.rule_name || (r.origen ? `Alerta · ${r.origen}` : 'Notificación'),
    status: r.status,
    createdAt: r.created_at,
    link: linkFor({ origen: r.origen, ruleId: r.alert_rule_id }),
  }));
}

/** Payload del evento socket 'notification:new'. */
export interface LiveNotification {
  tipo: string;
  ruleName: string | null;
  origen: string | null;
  status: string;
  at: string;
}
