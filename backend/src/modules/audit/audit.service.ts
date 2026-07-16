/**
 * Registro de auditoria: traza unificada de acciones de usuario en la app
 * (incluye inicios de sesion y fallidos). recordAudit NUNCA lanza: un fallo al
 * auditar no debe romper la accion que se estaba ejecutando.
 */
import type { Request } from 'express';
import { query } from '../../config/db';
import { logger } from '../../config/logger';

export interface AuditInput {
  actorId?: string | null;
  actorEmail?: string | null;
  action: string;
  target?: string | null;
  result?: 'ok' | 'fail';
  ip?: string | null;
  userAgent?: string | null;
  detail?: unknown;
}

export async function recordAudit(a: AuditInput): Promise<void> {
  try {
    await query(
      `INSERT INTO audit_log (actor_id, actor_email, action, target, result, ip, user_agent, detail)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)`,
      [
        a.actorId ?? null,
        a.actorEmail ?? null,
        a.action,
        a.target ?? null,
        a.result ?? 'ok',
        a.ip ?? null,
        a.userAgent ?? null,
        a.detail === undefined ? null : JSON.stringify(a.detail),
      ]
    );
  } catch (err) {
    logger.error({ err, action: a.action }, 'No se pudo registrar auditoria');
  }
}

/** Extrae IP + user-agent de la peticion (con trust proxy, req.ip es la IP real). */
export function auditFromReq(req: Request, a: Omit<AuditInput, 'ip' | 'userAgent'>): Promise<void> {
  return recordAudit({
    ...a,
    ip: req.ip ?? null,
    userAgent: (req.headers['user-agent'] as string | undefined)?.slice(0, 300) ?? null,
  });
}

export interface AuditItem {
  id: string;
  createdAt: string;
  actorEmail: string | null;
  action: string;
  target: string | null;
  result: 'ok' | 'fail';
  ip: string | null;
  detail: unknown;
}

export interface AuditFilters {
  action?: string;
  actorEmail?: string;
  result?: string;
  from?: string;
  to?: string;
  q?: string;
  limit?: number;
  offset?: number;
}

interface Row {
  id: string; created_at: string; actor_email: string | null; action: string;
  target: string | null; result: 'ok' | 'fail'; ip: string | null; detail: unknown;
}

export async function listAudit(f: AuditFilters): Promise<{ items: AuditItem[]; total: number }> {
  const limit = Math.min(Math.max(f.limit ?? 100, 1), 500);
  const offset = Math.max(f.offset ?? 0, 0);
  const where: string[] = [];
  const params: unknown[] = [];
  const p = (val: unknown): string => {
    params.push(val);
    return `$${params.length}`;
  };

  if (f.action) where.push(`action = ${p(f.action)}`);
  if (f.result) where.push(`result = ${p(f.result)}`);
  if (f.actorEmail) where.push(`actor_email ILIKE ${p(`%${f.actorEmail}%`)}`);
  if (f.from) where.push(`created_at >= ${p(f.from)}`);
  if (f.to) where.push(`created_at <= ${p(f.to)}`);
  if (f.q) {
    const like = `%${f.q}%`;
    where.push(`(target ILIKE ${p(like)} OR ip ILIKE ${p(like)} OR action ILIKE ${p(like)})`);
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

  const totalRows = await query<{ n: string }>(`SELECT count(*) n FROM audit_log ${whereSql}`, params);
  const total = Number(totalRows[0]?.n ?? 0);

  const rows = await query<Row>(
    `SELECT id, created_at, actor_email, action, target, result, ip, detail
       FROM audit_log ${whereSql}
      ORDER BY created_at DESC
      LIMIT ${limit} OFFSET ${offset}`,
    params
  );
  return {
    total,
    items: rows.map((r) => ({
      id: r.id, createdAt: r.created_at, actorEmail: r.actor_email, action: r.action,
      target: r.target, result: r.result, ip: r.ip, detail: r.detail,
    })),
  };
}

/** Acciones distintas presentes (para poblar el filtro del frontend). */
export async function auditActions(): Promise<string[]> {
  const rows = await query<{ action: string }>('SELECT DISTINCT action FROM audit_log ORDER BY action');
  return rows.map((r) => r.action);
}
