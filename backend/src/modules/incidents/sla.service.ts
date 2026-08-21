/**
 * Madurez de casos: política de SLA por severidad y métricas del SOC.
 *   - MTTA (Mean Time To Acknowledge): de creación a reconocimiento.
 *   - MTTR (Mean Time To Resolve): de creación a cierre.
 *   - MTTD (Mean Time To Detect): del evento (source.alertTime) a la creación.
 * Además calcula cumplimiento de SLA, carga por analista y antigüedad de abiertos.
 */
import { query } from '../../config/db';

export type Severity = 'critica' | 'alta' | 'media' | 'baja';
const CLOSED = ['resuelto', 'cerrado'];

export interface SlaPolicy { severity: Severity; ack_minutes: number; resolve_minutes: number }

export async function getPolicy(): Promise<SlaPolicy[]> {
  const rows = await query<SlaPolicy>('SELECT severity, ack_minutes, resolve_minutes FROM sla_policy');
  const order: Severity[] = ['critica', 'alta', 'media', 'baja'];
  return rows.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
}

export async function updatePolicy(input: { severity: string; ack_minutes: number; resolve_minutes: number }[]): Promise<SlaPolicy[]> {
  const valid: Severity[] = ['critica', 'alta', 'media', 'baja'];
  for (const p of Array.isArray(input) ? input : []) {
    if (!valid.includes(p.severity as Severity)) continue;
    const ack = Math.min(Math.max(Math.round(Number(p.ack_minutes)), 1), 100000);
    const res = Math.min(Math.max(Math.round(Number(p.resolve_minutes)), 1), 1000000);
    await query('UPDATE sla_policy SET ack_minutes = $2, resolve_minutes = $3 WHERE severity = $1', [p.severity, ack, res]);
  }
  return getPolicy();
}

// --- SLA por incidente ---
export type SlaState = 'ok' | 'due_soon' | 'breached' | 'met' | 'late';
export interface IncidentSla { ackDueAt: string; resolveDueAt: string; ackBreached: boolean; resolveBreached: boolean; state: SlaState }

interface SlaRow { severity: string; status: string; created_at: string; acknowledged_at: string | null; closed_at: string | null }

export function slaFor(row: SlaRow, policy: Map<string, SlaPolicy>, now = Date.now()): IncidentSla {
  const pol = policy.get(row.severity) ?? { severity: row.severity as Severity, ack_minutes: 120, resolve_minutes: 1440 };
  const created = new Date(row.created_at).getTime();
  const ackDue = created + pol.ack_minutes * 60000;
  const resDue = created + pol.resolve_minutes * 60000;
  const closed = CLOSED.includes(row.status);
  const ackAt = row.acknowledged_at ? new Date(row.acknowledged_at).getTime() : null;
  const closedAt = row.closed_at ? new Date(row.closed_at).getTime() : null;

  const ackBreached = ackAt != null ? ackAt > ackDue : (!closed && now > ackDue);
  const resolveBreached = closedAt != null ? closedAt > resDue : (!closed && now > resDue);

  let state: SlaState;
  if (closed) state = resolveBreached ? 'late' : 'met';
  else if (resolveBreached || ackBreached) state = 'breached';
  else if (now > resDue - (resDue - created) * 0.2) state = 'due_soon';
  else state = 'ok';

  return { ackDueAt: new Date(ackDue).toISOString(), resolveDueAt: new Date(resDue).toISOString(), ackBreached, resolveBreached, state };
}

// --- Recomendaciones: incidentes abiertos con SLA vencido (para escalar) ---
export interface BreachRec {
  id: string; title: string; severity: string; status: string;
  createdAt: string; assigneeName: string | null;
  ackBreached: boolean; resolveBreached: boolean; overdueMin: number;
}

export async function slaBreachedIncidents(): Promise<BreachRec[]> {
  const rows = await query<SlaRow & { id: string; title: string; assignee_name: string | null }>(
    `SELECT i.id, i.title, i.severity, i.status, i.created_at, i.acknowledged_at, i.closed_at,
            ua.full_name AS assignee_name
       FROM incidents i LEFT JOIN users ua ON ua.id = i.assignee_id
      WHERE i.status IN ('abierto','en_curso')`
  );
  const policy = new Map<string, SlaPolicy>((await getPolicy()).map((p) => [p.severity, p]));
  const now = Date.now();
  const out: BreachRec[] = [];
  for (const r of rows) {
    const sla = slaFor(r, policy, now);
    if (sla.state !== 'breached') continue;
    const due = new Date(sla.resolveBreached ? sla.resolveDueAt : sla.ackDueAt).getTime();
    out.push({
      id: r.id, title: r.title, severity: r.severity, status: r.status, createdAt: r.created_at,
      assigneeName: r.assignee_name, ackBreached: sla.ackBreached, resolveBreached: sla.resolveBreached,
      overdueMin: Math.round((now - due) / 60000),
    });
  }
  const order = ['critica', 'alta', 'media', 'baja'];
  out.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity) || b.overdueMin - a.overdueMin);
  return out;
}

// --- Métricas agregadas ---
export interface CaseMetrics {
  windowDays: number;
  counts: { total: number; abierto: number; en_curso: number; cerrados: number };
  mttaMinutes: number | null;
  mttrMinutes: number | null;
  mttdMinutes: number | null;
  sla: { resolveMet: number; resolveLate: number; compliancePct: number | null; openBreached: number };
  bySeverity: { severity: string; total: number; mttrMinutes: number | null; breached: number }[];
  workload: { assignee: string; name: string; open: number }[];
  aging: { bucket: string; count: number }[];
  throughput: { created7d: number; closed7d: number; created30d: number; closed30d: number };
}

interface MetricRow {
  id: string; severity: string; status: string; assignee_id: string | null; assignee_name: string | null;
  created_at: string; acknowledged_at: string | null; closed_at: string | null; alert_time: string | null;
}

function avg(nums: number[]): number | null {
  return nums.length ? Math.round(nums.reduce((a, b) => a + b, 0) / nums.length) : null;
}

export async function metrics(windowDays = 90): Promise<CaseMetrics> {
  const days = Math.min(Math.max(windowDays, 7), 365);
  const rows = await query<MetricRow>(
    `SELECT i.id, i.severity, i.status, i.assignee_id, ua.full_name AS assignee_name,
            i.created_at, i.acknowledged_at, i.closed_at, (i.source->>'alertTime') AS alert_time
       FROM incidents i LEFT JOIN users ua ON ua.id = i.assignee_id
      WHERE i.created_at > now() - ($1 || ' days')::interval`,
    [String(days)]
  );
  const policy = new Map((await getPolicy()).map((p) => [p.severity, p]));
  const now = Date.now();

  const mtta: number[] = [], mttr: number[] = [], mttd: number[] = [];
  const counts = { total: rows.length, abierto: 0, en_curso: 0, cerrados: 0 };
  let resolveMet = 0, resolveLate = 0, openBreached = 0;
  const sevMap = new Map<string, { total: number; mttr: number[]; breached: number }>();
  const workMap = new Map<string, { name: string; open: number }>();
  const aging = { '<1d': 0, '1-3d': 0, '3-7d': 0, '>7d': 0 };

  for (const r of rows) {
    const created = new Date(r.created_at).getTime();
    const closed = CLOSED.includes(r.status);
    if (r.status === 'abierto') counts.abierto++;
    else if (r.status === 'en_curso') counts.en_curso++;
    if (closed) counts.cerrados++;

    if (r.acknowledged_at) mtta.push((new Date(r.acknowledged_at).getTime() - created) / 60000);
    if (closed && r.closed_at) mttr.push((new Date(r.closed_at).getTime() - created) / 60000);
    if (r.alert_time) {
      const d = (created - new Date(r.alert_time).getTime()) / 60000;
      if (d >= 0 && d < 60 * 24 * 30) mttd.push(d);
    }

    const sla = slaFor(r, policy, now);
    if (closed) { if (sla.resolveBreached) resolveLate++; else resolveMet++; }
    else if (sla.state === 'breached') openBreached++;

    const sv = sevMap.get(r.severity) ?? { total: 0, mttr: [], breached: 0 };
    sv.total++;
    if (closed && r.closed_at) sv.mttr.push((new Date(r.closed_at).getTime() - created) / 60000);
    if (sla.resolveBreached) sv.breached++;
    sevMap.set(r.severity, sv);

    if (!closed) {
      const ageDays = (now - created) / 86400000;
      if (ageDays < 1) aging['<1d']++; else if (ageDays < 3) aging['1-3d']++; else if (ageDays < 7) aging['3-7d']++; else aging['>7d']++;
      if (r.assignee_id) {
        const w = workMap.get(r.assignee_id) ?? { name: r.assignee_name ?? 'usuario', open: 0 };
        w.open++; workMap.set(r.assignee_id, w);
      }
    }
  }

  const created7d = rows.filter((r) => now - new Date(r.created_at).getTime() < 7 * 86400000).length;
  const closed7d = rows.filter((r) => r.closed_at && now - new Date(r.closed_at).getTime() < 7 * 86400000).length;
  const created30d = rows.filter((r) => now - new Date(r.created_at).getTime() < 30 * 86400000).length;
  const closed30d = rows.filter((r) => r.closed_at && now - new Date(r.closed_at).getTime() < 30 * 86400000).length;

  const totalClosed = resolveMet + resolveLate;
  const order: Severity[] = ['critica', 'alta', 'media', 'baja'];

  return {
    windowDays: days,
    counts,
    mttaMinutes: avg(mtta),
    mttrMinutes: avg(mttr),
    mttdMinutes: avg(mttd),
    sla: { resolveMet, resolveLate, compliancePct: totalClosed ? Math.round((resolveMet / totalClosed) * 100) : null, openBreached },
    bySeverity: [...sevMap.entries()]
      .map(([severity, v]) => ({ severity, total: v.total, mttrMinutes: avg(v.mttr), breached: v.breached }))
      .sort((a, b) => order.indexOf(a.severity as Severity) - order.indexOf(b.severity as Severity)),
    workload: [...workMap.entries()].map(([assignee, v]) => ({ assignee, name: v.name, open: v.open })).sort((a, b) => b.open - a.open),
    aging: Object.entries(aging).map(([bucket, count]) => ({ bucket, count })),
    throughput: { created7d, closed7d, created30d, closed30d },
  };
}
