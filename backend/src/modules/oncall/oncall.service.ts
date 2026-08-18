/**
 * On-call (turnos de guardia): quién es el analista responsable en cada franja.
 * Alimenta el escalamiento de incidentes — cuando un caso sube de severidad o
 * vence el SLA, se notifica al analista de guardia por correo.
 */
import { query } from '../../config/db';
import { sendEmail, isEmailConfigured } from '../notifications/email.service';

export interface Shift {
  id: string;
  userId: string;
  userName: string;
  userEmail: string;
  startsAt: string;
  endsAt: string;
  note: string | null;
  createdBy: string | null;
}

interface Row {
  id: string; user_id: string; user_name: string; user_email: string;
  starts_at: string; ends_at: string; note: string | null; created_by: string | null;
}
const toShift = (r: Row): Shift => ({
  id: r.id, userId: r.user_id, userName: r.user_name, userEmail: r.user_email,
  startsAt: r.starts_at, endsAt: r.ends_at, note: r.note, createdBy: r.created_by,
});

const SELECT = `SELECT s.id, s.user_id, u.full_name AS user_name, u.email AS user_email,
                       s.starts_at, s.ends_at, s.note, s.created_by
                FROM oncall_shifts s JOIN users u ON u.id = s.user_id`;

/** Turnos que solapan la ventana [from, to] (ISO). */
export async function listShifts(fromISO: string, toISO: string): Promise<Shift[]> {
  const rows = await query<Row>(
    `${SELECT} WHERE s.ends_at > $1 AND s.starts_at < $2 ORDER BY s.starts_at ASC`,
    [fromISO, toISO],
  );
  return rows.map(toShift);
}

/** Turno vigente ahora (el más reciente que cubre now()), o null. */
export async function currentOnCall(): Promise<Shift | null> {
  const rows = await query<Row>(
    `${SELECT} WHERE s.starts_at <= now() AND s.ends_at > now() ORDER BY s.starts_at DESC LIMIT 1`,
  );
  return rows[0] ? toShift(rows[0]) : null;
}

export async function createShift(input: { userId: string; startsAt: string; endsAt: string; note?: string }, createdBy: string): Promise<Shift> {
  const rows = await query<{ id: string }>(
    `INSERT INTO oncall_shifts (user_id, starts_at, ends_at, note, created_by)
     VALUES ($1, $2, $3, $4, $5) RETURNING id`,
    [input.userId, input.startsAt, input.endsAt, input.note?.trim() || null, createdBy],
  );
  const full = await query<Row>(`${SELECT} WHERE s.id = $1`, [rows[0].id]);
  return toShift(full[0]);
}

export async function deleteShift(id: string): Promise<void> {
  await query('DELETE FROM oncall_shifts WHERE id = $1', [id]);
}

/** Admins activos, como respaldo cuando no hay nadie de guardia. */
async function activeAdminEmails(): Promise<string[]> {
  const rows = await query<{ email: string }>(
    `SELECT u.email FROM users u JOIN roles r ON r.id = u.role_id
     WHERE u.is_active = TRUE AND r.name = 'admin'`,
  ).catch(() => [] as { email: string }[]);
  return rows.map((r) => r.email).filter(Boolean);
}

export interface EscalationResult { delivered: boolean; to: string[]; onCall: string | null; reason: string }

/**
 * Notifica por correo al analista de guardia (o a los admins como respaldo).
 * Lo usa el escalamiento de incidentes (#4).
 */
export async function notifyOnCall(subject: string, bodyText: string): Promise<EscalationResult> {
  const shift = await currentOnCall();
  const to = shift ? [shift.userEmail] : await activeAdminEmails();
  const reason = shift ? `guardia: ${shift.userName}` : 'sin guardia asignada → admins';
  if (!isEmailConfigured() || to.length === 0) {
    return { delivered: false, to, onCall: shift?.userName ?? null, reason: isEmailConfigured() ? 'sin destinatarios' : 'SMTP no configurado' };
  }
  const html = `<p>${bodyText.replace(/\n/g, '<br>')}</p><hr><p style="color:#888;font-size:12px">HexWatch · escalamiento on-call (${reason})</p>`;
  try {
    await sendEmail(to, `[HexWatch] ${subject}`, html, bodyText);
    return { delivered: true, to, onCall: shift?.userName ?? null, reason };
  } catch {
    return { delivered: false, to, onCall: shift?.userName ?? null, reason: 'fallo al enviar correo' };
  }
}
