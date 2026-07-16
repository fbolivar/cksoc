/** Tipos y API de Gestion de Incidentes. */
import { api } from './api';

export type Severity = 'baja' | 'media' | 'alta' | 'critica';
export type Status = 'abierto' | 'en_curso' | 'resuelto' | 'cerrado';

export interface IncidentListItem {
  id: string; title: string; severity: Severity; status: Status;
  assigneeId: string | null; assigneeName: string | null; creatorName: string | null;
  notes: number; createdAt: string; updatedAt: string;
}

export interface IncidentNote {
  id: string; authorName: string | null; kind: 'comment' | 'system'; note: string; createdAt: string;
}

export interface IncidentSource {
  alertId?: string; index?: string; ip?: string; agent?: string; ruleId?: string; description?: string; alertTime?: string;
}

export interface IncidentDetail extends IncidentListItem {
  description: string | null;
  source: IncidentSource;
  createdBy: string | null;
  closedAt: string | null;
  timeline: IncidentNote[];
}

export const incidentsApi = {
  list: (f: { status?: string; severity?: string; assignee?: string; q?: string } = {}) =>
    api.get<{ incidents: IncidentListItem[] }>('/incidents', { params: f }).then((r) => r.data.incidents),
  get: (id: string) => api.get<IncidentDetail>(`/incidents/${id}`).then((r) => r.data),
  create: (d: { title: string; description?: string; severity: Severity; source?: IncidentSource }) =>
    api.post<IncidentDetail>('/incidents', d).then((r) => r.data),
  update: (id: string, p: { status?: Status; severity?: Severity; assigneeId?: string | null }) =>
    api.patch<IncidentDetail>(`/incidents/${id}`, p).then((r) => r.data),
  addNote: (id: string, note: string) =>
    api.post<IncidentDetail>(`/incidents/${id}/notes`, { note }).then((r) => r.data),
  users: () => api.get<{ users: { id: string; name: string; role: string }[] }>('/incidents/meta/users').then((r) => r.data.users),
};

export const SEV: Record<Severity, { color: string; label: string }> = {
  baja: { color: '#22c55e', label: 'Baja' },
  media: { color: '#eab308', label: 'Media' },
  alta: { color: '#f97316', label: 'Alta' },
  critica: { color: '#ef4444', label: 'Crítica' },
};
export const ST: Record<Status, { color: string; label: string }> = {
  abierto: { color: '#f59e0b', label: 'Abierto' },
  en_curso: { color: '#3b82f6', label: 'En curso' },
  resuelto: { color: '#22c55e', label: 'Resuelto' },
  cerrado: { color: '#94a3b8', label: 'Cerrado' },
};
