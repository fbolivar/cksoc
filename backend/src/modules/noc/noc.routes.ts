/**
 * NOC — Monitoreo de disponibilidad. Admin/analista.
 *   GET    /api/noc/overview
 *   POST   /api/noc/targets        { name, host, kind?, port?, path?, grupo? }
 *   PUT    /api/noc/targets/:id     { enabled }
 *   DELETE /api/noc/targets/:id
 *   POST   /api/noc/check           (corre los chequeos ahora)
 * Scheduler: chequea cada NOC_CRON (def. cada 2 min) y avisa por Telegram (CKAgentico)
 * cuando un objetivo cae o se recupera (gateado por licencia).
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { sendTelegram } from '../notifications/telegram.service';
import { getOverview, addTarget, setEnabled, deleteTarget, runChecks, ensureNocSchema, isNocEnabled } from './noc.service';

export const nocRouter = Router();
nocRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en NOC');
  res.status(500).json({ error: 'Error interno del servidor' });
}

nocRouter.get('/overview', canManage, async (_req, res) => { try { res.json(await getOverview()); } catch (e) { handle(e, res); } });
nocRouter.post('/targets', canManage, async (req, res) => {
  try {
    const name = String(req.body?.name ?? '').trim(); const host = String(req.body?.host ?? '').trim();
    if (!name || !host) { res.status(400).json({ error: 'name y host requeridos' }); return; }
    const kind = req.body?.kind; const port = req.body?.port != null ? Number(req.body.port) : null;
    if (kind === 'tcp' && (!port || port < 1 || port > 65535)) { res.status(400).json({ error: 'puerto inválido para TCP' }); return; }
    const id = await addTarget({ name, host, kind, port, path: req.body?.path ? String(req.body.path) : null, grupo: req.body?.grupo ? String(req.body.grupo) : undefined });
    res.status(201).json({ id });
  } catch (e) { handle(e, res); }
});
nocRouter.put('/targets/:id', canManage, async (req, res) => {
  try { await setEnabled(req.params.id, req.body?.enabled === true || req.body?.enabled === 'true'); res.json({ ok: true }); } catch (e) { handle(e, res); }
});
nocRouter.delete('/targets/:id', canManage, async (req, res) => {
  try { await deleteTarget(req.params.id); res.json({ ok: true }); } catch (e) { handle(e, res); }
});
nocRouter.post('/check', canManage, async (_req, res) => {
  try { const r = await runChecks(); res.json({ ok: true, ...r }); } catch (e) { handle(e, res); }
});

async function alertTransitions(trans: { name: string; host: string; to: string; downMin: number | null }[]): Promise<void> {
  if (!trans.length || !env.TELEGRAM_CHAT_ID) return;
  const down = trans.filter((t) => t.to === 'down');
  const up = trans.filter((t) => t.to === 'up');
  const L: string[] = ['📡 CKAgentico · NOC — cambios de disponibilidad', ''];
  for (const t of down) L.push(`🔴 ${t.name} (${t.host}) NO responde — caído.`);
  for (const t of up) L.push(`🟢 ${t.name} (${t.host}) se recuperó${t.downMin != null ? ` (estuvo caído ~${t.downMin} min)` : ''}.`);
  if (down.length) L.push('', 'Si es un equipo del cliente, puede requerir revisión en sitio (Ricardo).');
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
}

/** Scheduler del NOC: chequeo periódico + aviso por transición. */
export function startNocScheduler(): void {
  if (!isNocEnabled()) { logger.info('📡 NOC desactivado (NOC_ENABLED=false)'); return; }
  void ensureNocSchema().catch((e) => logger.error({ err: e }, 'NOC: no se pudo preparar el esquema'));
  const spec = process.env.NOC_CRON || '*/2 * * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de NOC inválido'); return; }
  cron.schedule(spec, async () => {
    try { const r = await runChecks(); if (r.transitions.length) { logger.info({ transiciones: r.transitions.length }, '📡 NOC: cambios de disponibilidad'); await alertTransitions(r.transitions); } }
    catch (e) { logger.error({ err: e }, 'NOC: error en chequeo programado'); }
  });
  setTimeout(() => { void runChecks().catch(() => undefined); }, 15_000); // primera pasada al arranque
  logger.info(`📡 NOC activo (${spec})`);
}
