/**
 * Gestion de incidentes/casos del SOC: ciclo de vida (abierto -> en curso ->
 * resuelto/cerrado), asignacion, notas y timeline de eventos del sistema.
 */
import { query } from '../../config/db';
import { getPolicy, slaFor, type IncidentSla, type SlaPolicy } from './sla.service';
import { notifyOnCall } from '../oncall/oncall.service';

export type Severity = 'baja' | 'media' | 'alta' | 'critica';

/** Ranking de severidad para detectar escalamientos. */
const SEV_RANK: Record<string, number> = { baja: 1, media: 2, alta: 3, critica: 4 };
/** Dispara el escalamiento on-call sin bloquear la respuesta. */
function escalate(subject: string, body: string): void {
  void notifyOnCall(subject, body).catch(() => undefined);
}
export type Status = 'abierto' | 'en_curso' | 'resuelto' | 'cerrado';

export interface IncidentSource {
  alertId?: string; index?: string; ip?: string; agent?: string; ruleId?: string; description?: string; alertTime?: string;
}

export interface IncidentListItem {
  id: string;
  title: string;
  severity: Severity;
  status: Status;
  assigneeId: string | null;
  assigneeName: string | null;
  creatorName: string | null;
  notes: number;
  createdAt: string;
  updatedAt: string;
  sla: IncidentSla;
}

export interface IncidentNote {
  id: string;
  authorName: string | null;
  kind: 'comment' | 'system';
  note: string;
  createdAt: string;
}

export interface IncidentDetail extends IncidentListItem {
  description: string | null;
  source: IncidentSource;
  createdBy: string | null;
  closedAt: string | null;
  timeline: IncidentNote[];
}

const CLOSED: Status[] = ['resuelto', 'cerrado'];

interface ListRow {
  id: string; title: string; severity: Severity; status: Status;
  assignee_id: string | null; assignee_name: string | null; creator_name: string | null;
  notes: string; created_at: string; updated_at: string;
  acknowledged_at: string | null; closed_at: string | null;
}

export async function listIncidents(f: { status?: string; severity?: string; assignee?: string; q?: string }): Promise<IncidentListItem[]> {
  const rows = await query<ListRow>(
    `SELECT i.id, i.title, i.severity, i.status, i.assignee_id,
            ua.full_name AS assignee_name, uc.full_name AS creator_name,
            (SELECT count(*) FROM incident_notes n WHERE n.incident_id = i.id AND n.kind = 'comment') AS notes,
            i.created_at, i.updated_at, i.acknowledged_at, i.closed_at
       FROM incidents i
       LEFT JOIN users ua ON ua.id = i.assignee_id
       LEFT JOIN users uc ON uc.id = i.created_by
      WHERE ($1::text IS NULL OR i.status = $1)
        AND ($2::text IS NULL OR i.severity = $2)
        AND ($3::uuid IS NULL OR i.assignee_id = $3::uuid)
        AND ($4::text IS NULL OR i.title ILIKE '%' || $4 || '%')
      ORDER BY (i.status IN ('resuelto','cerrado')) ASC, i.created_at DESC
      LIMIT 200`,
    [f.status ?? null, f.severity ?? null, f.assignee ?? null, f.q ?? null]
  );
  const policy = new Map<string, SlaPolicy>((await getPolicy()).map((p) => [p.severity, p]));
  const now = Date.now();
  return rows.map((r) => ({
    id: r.id, title: r.title, severity: r.severity, status: r.status,
    assigneeId: r.assignee_id, assigneeName: r.assignee_name, creatorName: r.creator_name,
    notes: Number(r.notes), createdAt: r.created_at, updatedAt: r.updated_at,
    sla: slaFor(r, policy, now),
  }));
}

export async function getIncident(id: string): Promise<IncidentDetail | null> {
  const rows = await query<ListRow & { description: string | null; source: IncidentSource; created_by: string | null; closed_at: string | null }>(
    `SELECT i.id, i.title, i.description, i.severity, i.status, i.assignee_id,
            ua.full_name AS assignee_name, uc.full_name AS creator_name,
            i.created_by, i.source, i.closed_at, i.acknowledged_at, i.created_at, i.updated_at,
            0 AS notes
       FROM incidents i
       LEFT JOIN users ua ON ua.id = i.assignee_id
       LEFT JOIN users uc ON uc.id = i.created_by
      WHERE i.id = $1`,
    [id]
  );
  const r = rows[0];
  if (!r) return null;
  const timeline = await query<{ id: string; author_name: string | null; kind: 'comment' | 'system'; note: string; created_at: string }>(
    `SELECT id, author_name, kind, note, created_at FROM incident_notes WHERE incident_id = $1 ORDER BY created_at ASC`,
    [id]
  );
  const policy = new Map<string, SlaPolicy>((await getPolicy()).map((p) => [p.severity, p]));
  return {
    id: r.id, title: r.title, description: r.description, severity: r.severity, status: r.status,
    assigneeId: r.assignee_id, assigneeName: r.assignee_name, creatorName: r.creator_name,
    createdBy: r.created_by, source: r.source ?? {}, closedAt: r.closed_at,
    notes: 0, createdAt: r.created_at, updatedAt: r.updated_at,
    sla: slaFor(r, policy),
    timeline: timeline.map((t) => ({ id: t.id, authorName: t.author_name, kind: t.kind, note: t.note, createdAt: t.created_at })),
  };
}

async function addSystemNote(incidentId: string, userId: string, note: string): Promise<void> {
  await query(
    `INSERT INTO incident_notes (incident_id, author_id, author_name, kind, note)
     VALUES ($1, $2, (SELECT full_name FROM users WHERE id = $2), 'system', $3)`,
    [incidentId, userId, note]
  );
}

export async function createIncident(
  data: { title: string; description?: string; severity: Severity; source?: IncidentSource },
  userId: string
): Promise<IncidentDetail> {
  const rows = await query<{ id: string }>(
    `INSERT INTO incidents (title, description, severity, created_by, source)
     VALUES ($1, $2, $3, $4, $5::jsonb) RETURNING id`,
    [data.title, data.description ?? null, data.severity, userId, JSON.stringify(data.source ?? {})]
  );
  const id = rows[0].id;
  await addSystemNote(id, userId, 'Incidente creado.');
  // Escala al analista de guardia si nace crítico/alto.
  if (data.severity === 'critica' || data.severity === 'alta') {
    escalate(`Nuevo incidente ${data.severity}: ${data.title}`,
      `Se creó un incidente de severidad ${data.severity.toUpperCase()}.\n\nTítulo: ${data.title}${data.description ? `\n\n${data.description}` : ''}\n\nAtiéndelo en HexWatch → Incidentes.`);
  }
  return (await getIncident(id))!;
}

export async function addComment(id: string, note: string, userId: string): Promise<IncidentDetail | null> {
  const exists = await query<{ id: string }>('SELECT id FROM incidents WHERE id = $1', [id]);
  if (!exists[0]) return null;
  await query(
    `INSERT INTO incident_notes (incident_id, author_id, author_name, kind, note)
     VALUES ($1, $2, (SELECT full_name FROM users WHERE id = $2), 'comment', $3)`,
    [id, userId, note]
  );
  await query('UPDATE incidents SET updated_at = now() WHERE id = $1', [id]);
  return getIncident(id);
}

export async function updateIncident(
  id: string,
  patch: { status?: Status; severity?: Severity; assigneeId?: string | null },
  userId: string
): Promise<IncidentDetail | null> {
  const cur = (await query<{ status: Status; severity: Severity; assignee_id: string | null; title: string }>(
    'SELECT status, severity, assignee_id, title FROM incidents WHERE id = $1', [id]
  ))[0];
  if (!cur) return null;

  const sysNotes: string[] = [];
  const sets: string[] = ['updated_at = now()'];
  const params: unknown[] = [];
  let p = 1;

  if (patch.status && patch.status !== cur.status) {
    sets.push(`status = $${p++}`); params.push(patch.status);
    sysNotes.push(`Estado: ${cur.status} → ${patch.status}.`);
    if (CLOSED.includes(patch.status)) sets.push('closed_at = now()');
    else if (CLOSED.includes(cur.status)) sets.push('closed_at = NULL');
    // El caso deja de estar "abierto" → primer reconocimiento (MTTA).
    if (cur.status === 'abierto' && patch.status !== 'abierto') sets.push('acknowledged_at = COALESCE(acknowledged_at, now())');
  }
  if (patch.severity && patch.severity !== cur.severity) {
    sets.push(`severity = $${p++}`); params.push(patch.severity);
    sysNotes.push(`Severidad: ${cur.severity} → ${patch.severity}.`);
  }
  if (patch.assigneeId !== undefined && patch.assigneeId !== cur.assignee_id) {
    sets.push(`assignee_id = $${p++}`); params.push(patch.assigneeId);
    if (patch.assigneeId) {
      sets.push('acknowledged_at = COALESCE(acknowledged_at, now())'); // asignar = reconocer
      const name = (await query<{ full_name: string }>('SELECT full_name FROM users WHERE id = $1', [patch.assigneeId]))[0];
      sysNotes.push(`Asignado a ${name?.full_name ?? 'usuario'}.`);
    } else {
      sysNotes.push('Asignación removida.');
    }
  }

  params.push(id);
  await query(`UPDATE incidents SET ${sets.join(', ')} WHERE id = $${p}`, params);
  for (const n of sysNotes) await addSystemNote(id, userId, n);
  // Escala si la severidad SUBIÓ a alta/crítica.
  if (patch.severity && patch.severity !== cur.severity
      && (SEV_RANK[patch.severity] ?? 0) > (SEV_RANK[cur.severity] ?? 0)
      && (patch.severity === 'critica' || patch.severity === 'alta')) {
    escalate(`Incidente escaló a ${patch.severity}: ${cur.title}`,
      `El incidente "${cur.title}" subió de ${cur.severity.toUpperCase()} a ${patch.severity.toUpperCase()}.\n\nAtiéndelo en HexWatch → Incidentes.`);
  }
  return getIncident(id);
}

export async function assignableUsers(): Promise<{ id: string; name: string; role: string }[]> {
  const rows = await query<{ id: string; full_name: string; role: string }>(
    `SELECT u.id, u.full_name, r.name AS role
       FROM users u JOIN roles r ON r.id = u.role_id
      WHERE u.is_active = TRUE AND r.name IN ('admin','analista')
      ORDER BY u.full_name`
  );
  return rows.map((r) => ({ id: r.id, name: r.full_name, role: r.role }));
}
