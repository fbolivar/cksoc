/** Feed de notificaciones para la campanita (reusa /api/notifications/log). */
import { api } from './api';

export interface FeedItem {
  id: string;
  title: string;
  status: 'sent' | 'failed' | 'skipped' | string;
  createdAt: string;
  live?: boolean;
}

interface LogRow {
  id: string;
  rule_name: string | null;
  origen?: string | null;
  status: string;
  created_at: string;
}

export async function fetchFeed(): Promise<FeedItem[]> {
  const { data } = await api.get<{ log: LogRow[] }>('/notifications/log');
  return (data.log ?? []).map((r) => ({
    id: r.id,
    title: r.rule_name || (r.origen ? `Alerta · ${r.origen}` : 'Notificación'),
    status: r.status,
    createdAt: r.created_at,
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
