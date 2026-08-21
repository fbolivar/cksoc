/** Tipos y API de Gestion de Incidentes. */
import { api } from './api';

export type Severity = 'baja' | 'media' | 'alta' | 'critica';
export type Status = 'abierto' | 'en_curso' | 'resuelto' | 'cerrado';

export type SlaState = 'ok' | 'due_soon' | 'breached' | 'met' | 'late';
export interface IncidentSla {
  ackDueAt: string; resolveDueAt: string; ackBreached: boolean; resolveBreached: boolean; state: SlaState;
}

export interface IncidentListItem {
  id: string; title: string; severity: Severity; status: Status;
  assigneeId: string | null; assigneeName: string | null; creatorName: string | null;
  notes: number; createdAt: string; updatedAt: string; sla: IncidentSla;
}

export interface SlaPolicy { severity: Severity; ack_minutes: number; resolve_minutes: number }

export interface CaseMetrics {
  windowDays: number;
  counts: { total: number; abierto: number; en_curso: number; cerrados: number };
  mttaMinutes: number | null;
  mttrMinutes: number | null;
  mttdMinutes: number | null;
  sla: { resolveMet: number; resolveLate: number; compliancePct: number | null; openBreached: number };
  bySeverity: { severity: Severity; total: number; mttrMinutes: number | null; breached: number }[];
  workload: { assignee: string; name: string; open: number }[];
  aging: { bucket: string; count: number }[];
  throughput: { created7d: number; closed7d: number; created30d: number; closed30d: number };
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

export interface BreachRec {
  id: string; title: string; severity: Severity; status: Status;
  createdAt: string; assigneeName: string | null;
  ackBreached: boolean; resolveBreached: boolean; overdueMin: number;
}

export const incidentsApi = {
  recommendations: () => api.get<{ items: BreachRec[] }>('/incidents/recommendations').then((r) => r.data.items),
  escalate: (id: string) => api.post<{ escalated: boolean; delivered: boolean; onCall: string | null; reason: string }>(`/incidents/${id}/escalate`, {}).then((r) => r.data),
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
  metrics: (days = 90) => api.get<CaseMetrics>('/incidents/metrics', { params: { days } }).then((r) => r.data),
  sla: () => api.get<{ policy: SlaPolicy[] }>('/incidents/sla').then((r) => r.data.policy),
  updateSla: (policy: SlaPolicy[]) => api.put<{ policy: SlaPolicy[] }>('/incidents/sla', { policy }).then((r) => r.data.policy),
};

/** Etiqueta y color del estado de SLA de un caso. */
export const SLA_STATE: Record<SlaState, { label: string; cls: string }> = {
  ok: { label: 'En plazo', cls: 'text-emerald-700 bg-emerald-500/10 border-emerald-500/30' },
  due_soon: { label: 'Por vencer', cls: 'text-amber-700 bg-amber-500/10 border-amber-500/30' },
  breached: { label: 'SLA incumplido', cls: 'text-rose-700 bg-rose-500/10 border-rose-500/30' },
  met: { label: 'Cumplido', cls: 'text-emerald-700 bg-emerald-500/10 border-emerald-500/30' },
  late: { label: 'Tarde', cls: 'text-rose-700 bg-rose-500/10 border-rose-500/30' },
};

/** Formatea minutos como "2h 15m" o "3d 4h". */
export function fmtDuration(min: number | null): string {
  if (min == null) return '—';
  if (min < 60) return `${Math.round(min)}m`;
  if (min < 1440) return `${Math.floor(min / 60)}h ${Math.round(min % 60)}m`;
  return `${Math.floor(min / 1440)}d ${Math.floor((min % 1440) / 60)}h`;
}

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
