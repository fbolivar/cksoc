/**
 * Gestion de incidentes/casos del SOC: ciclo de vida (abierto -> en curso ->
 * resuelto/cerrado), asignacion, notas y timeline de eventos del sistema.
 */
import { query } from '../../config/db';
import { HttpError } from '../auth/auth.service';
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

/** Clasificación del incidente al cerrarlo: distingue lo real del ruido para que
 *  las métricas (MTTR/SLA) no midan falsos positivos ni pruebas. */
export type Disposition = 'verdadero_positivo' | 'falso_positivo' | 'prueba';

export interface IncidentDetail extends IncidentListItem {
  description: string | null;
  source: IncidentSource;
  createdBy: string | null;
  closedAt: string | null;
  disposition: Disposition | null;
  timeline: IncidentNote[];
}

const CLOSED: Status[] = ['resuelto', 'cerrado'];
const DISPOSITION_LABEL: Record<Disposition, string> = {
  verdadero_positivo: 'Verdadero positivo',
  falso_positivo: 'Falso positivo',
  prueba: 'Prueba / benigno',
};

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
  const rows = await query<ListRow & { description: string | null; source: IncidentSource; created_by: string | null; closed_at: string | null; disposition: Disposition | null }>(
    `SELECT i.id, i.title, i.description, i.severity, i.status, i.assignee_id,
            ua.full_name AS assignee_name, uc.full_name AS creator_name,
            i.created_by, i.source, i.closed_at, i.disposition, i.acknowledged_at, i.created_at, i.updated_at,
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
    disposition: r.disposition ?? null,
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

// Ventana para deduplicar creación automática: un mismo evento (mismo alertId o
// firma regla+host) no debe abrir un caso nuevo si ya hay uno abierto o reciente.
const DEDUP_WINDOW_H = 24;

/** Busca un incidente vivo (abierto/en curso) o reciente (<24h) con la misma firma. */
async function findDuplicateIncident(dedupKey: string): Promise<string | null> {
  const rows = await query<{ id: string }>(
    `SELECT id FROM incidents
      WHERE source->>'dedupKey' = $1
        AND (status IN ('abierto','en_curso') OR created_at > now() - interval '${DEDUP_WINDOW_H} hours')
      ORDER BY created_at ASC LIMIT 1`,
    [dedupKey]
  );
  return rows[0]?.id ?? null;
}

export async function createIncident(
  data: { title: string; description?: string; severity: Severity; source?: IncidentSource; dedupKey?: string; autoAck?: boolean },
  userId: string
): Promise<IncidentDetail> {
  // Dedup solo en creación automática (SOAR/playbooks pasan dedupKey). Manual siempre crea.
  if (data.dedupKey) {
    const dupId = await findDuplicateIncident(data.dedupKey);
    if (dupId) {
      // Cuenta recurrencias previas para numerar (original = ×1).
      const [{ n } = { n: 0 }] = await query<{ n: number }>(
        `SELECT count(*)::int AS n FROM incident_notes WHERE incident_id = $1 AND kind = 'system' AND note LIKE 'Recurrencia%'`,
        [dupId]
      );
      await addSystemNote(dupId, userId, `Recurrencia (×${n + 2}): se recibió de nuevo el mismo evento (${data.title}). No se creó un incidente duplicado ni se re-escaló.`);
      await query('UPDATE incidents SET updated_at = now() WHERE id = $1', [dupId]);
      return (await getIncident(dupId))!;
    }
  }

  // Guarda la firma dentro de source para deduplicar recurrencias futuras.
  const source: IncidentSource & { dedupKey?: string } = { ...(data.source ?? {}), ...(data.dedupKey ? { dedupKey: data.dedupKey } : {}) };
  const rows = await query<{ id: string }>(
    `INSERT INTO incidents (title, description, severity, created_by, source, acknowledged_at)
     VALUES ($1, $2, $3, $4, $5::jsonb, $6) RETURNING id`,
    [data.title, data.description ?? null, data.severity, userId, JSON.stringify(source), data.autoAck ? new Date() : null]
  );
  const id = rows[0].id;
  await addSystemNote(id, userId, data.autoAck ? 'Incidente creado y reconocido automaticamente (generado por automatizacion SOAR; ya contenido/notificado). No arranca el SLA de reconocimiento humano.' : 'Incidente creado.');
  // Escala al analista de guardia si nace crítico/alto (solo la PRIMERA vez, no en recurrencias).
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
  patch: { status?: Status; severity?: Severity; assigneeId?: string | null; disposition?: Disposition | null },
  userId: string
): Promise<IncidentDetail | null> {
  const cur = (await query<{ status: Status; severity: Severity; assignee_id: string | null; title: string; disposition: Disposition | null }>(
    'SELECT status, severity, assignee_id, title, disposition FROM incidents WHERE id = $1', [id]
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
  if (patch.disposition !== undefined && patch.disposition !== cur.disposition) {
    sets.push(`disposition = $${p++}`); params.push(patch.disposition);
    sysNotes.push(patch.disposition
      ? `Clasificado como: ${DISPOSITION_LABEL[patch.disposition]}.`
      : 'Clasificación removida.');
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

/** Escala manualmente un incidente al analista de guardia (SLA vencido). */
export async function escalateIncident(id: string, userId: string): Promise<{ escalated: true; delivered: boolean; to: string[]; onCall: string | null; reason: string }> {
  const inc = (await query<{ title: string; severity: string; status: string }>(
    'SELECT title, severity, status FROM incidents WHERE id = $1', [id]
  ))[0];
  if (!inc) throw new HttpError(404, 'Incidente no encontrado');
  const res = await notifyOnCall(
    `Escalamiento (SLA vencido): ${inc.severity} "${inc.title}"`,
    `El incidente "${inc.title}" (severidad ${inc.severity.toUpperCase()}, estado ${inc.status}) tiene el SLA VENCIDO y fue escalado manualmente.\n\nAtiéndelo en HexWatch → Incidentes.`
  );
  await addSystemNote(id, userId, `Escalado al on-call${res.onCall ? ` (${res.onCall})` : ''}: ${res.delivered ? 'notificación enviada' : `no entregada (${res.reason})`}.`);
  await query('UPDATE incidents SET updated_at = now() WHERE id = $1', [id]);
  return { escalated: true, ...res };
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
