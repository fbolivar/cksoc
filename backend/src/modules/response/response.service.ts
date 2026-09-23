/**
 * Orquestacion de la respuesta semi-automatica.
 * SIEMPRE: valida lista blanca -> ejecuta en FortiGate -> registra en auditoria.
 * Ninguna accion ocurre sin pasar por aqui.
 */
import { query } from '../../config/db';
import { HttpError } from '../auth/auth.service';
import { canBlock } from './whitelist';
import { blockIP, unblockIP, listBlocked as fgListBlocked } from './sonicwall.service';

export interface ActingUser {
  id: string;
  email: string;
}

export interface BlockedItem {
  ip: string;
  motivo: string | null;
  usuario_email: string | null;
  blocked_at: string | null;
  permanent: boolean;
  expiresAt: number | null; // epoch ms; null si permanente
}

async function logAction(
  ip: string,
  accion: 'block' | 'unblock',
  motivo: string | null,
  user: ActingUser,
  resultado: 'success' | 'failed' | 'rejected',
  detalle: string | null,
  alertaOrigenId?: string
): Promise<void> {
  await query(
    `INSERT INTO block_actions
       (ip, accion, motivo, usuario_id, usuario_email, resultado, detalle, alerta_origen_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
    [ip, accion, motivo, user.id, user.email, resultado, detalle, alertaOrigenId ?? null]
  );
}

/** Bloquea una IP tras validar lista blanca. Registra el resultado siempre. */
export async function block(opts: {
  ip: string;
  motivo: string;
  user: ActingUser;
  adminIp?: string;
  alertaOrigenId?: string;
  /** Duración del ban; 0 = permanente. Si se omite, usa el default (24h) — lo
   *  usan los bloqueos automáticos (SOAR). El bloqueo MANUAL pasa 0 (permanente). */
  expirySeconds?: number;
}): Promise<void> {
  // 1) Validacion de seguridad (lista blanca) — ANTES de tocar el FortiGate
  const check = canBlock(opts.ip, opts.adminIp);
  if (!check.allowed) {
    await logAction(opts.ip, 'block', opts.motivo, opts.user, 'rejected', check.reason ?? null, opts.alertaOrigenId);
    throw new HttpError(400, check.reason ?? 'Bloqueo rechazado por la lista blanca');
  }
  // 2) Ejecucion + auditoria
  try {
    await blockIP(opts.ip, opts.expirySeconds);
    await logAction(opts.ip, 'block', opts.motivo, opts.user, 'success', null, opts.alertaOrigenId);
  } catch (err) {
    const detalle = err instanceof Error ? err.message : 'error desconocido';
    await logAction(opts.ip, 'block', opts.motivo, opts.user, 'failed', detalle, opts.alertaOrigenId);
    throw err;
  }
}

/** Desbloquea una IP (revertir). Registra el resultado siempre. */
export async function unblock(opts: { ip: string; user: ActingUser }): Promise<void> {
  try {
    await unblockIP(opts.ip);
    await logAction(opts.ip, 'unblock', null, opts.user, 'success', null);
  } catch (err) {
    const detalle = err instanceof Error ? err.message : 'error desconocido';
    await logAction(opts.ip, 'unblock', null, opts.user, 'failed', detalle);
    throw err;
  }
}

/** Lista las IPs bloqueadas por la app (lee el FortiGate) enriquecidas con auditoria. */
export async function listBlocked(): Promise<BlockedItem[]> {
  const blocked = await fgListBlocked();
  const result: BlockedItem[] = [];
  for (const b of blocked) {
    const rows = await query<{ motivo: string | null; usuario_email: string | null; created_at: string }>(
      `SELECT motivo, usuario_email, created_at FROM block_actions
        WHERE ip = $1 AND accion = 'block' AND resultado = 'success'
        ORDER BY created_at DESC LIMIT 1`,
      [b.ip]
    );
    result.push({
      ip: b.ip,
      motivo: rows[0]?.motivo ?? null,
      usuario_email: rows[0]?.usuario_email ?? null,
      blocked_at: rows[0]?.created_at ?? null,
      permanent: b.permanent,
      expiresAt: b.expiresAt,
    });
  }
  return result;
}

/** Historico completo de acciones (auditoria). */
export async function history(limit = 100) {
  return query(
    `SELECT id, ip, accion, motivo, usuario_email, resultado, detalle, alerta_origen_id, created_at
       FROM block_actions ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );
}
