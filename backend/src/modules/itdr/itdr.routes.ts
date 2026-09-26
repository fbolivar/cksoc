/**
 * ITDR avanzado — amenazas de identidad sobre logins O365. Admin/analista.
 *   GET    /api/itdr/overview
 *   GET    /api/itdr/findings?estado=&tipo=
 *   POST   /api/itdr/scan               { range }
 *   PUT    /api/itdr/findings/:id/status { estado }
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { sendTelegram } from '../notifications/telegram.service';
import { isItdrEnabled, scan, getOverview, listFindings, setStatus, buildTelegramReport } from './itdr.service';

export const itdrRouter = Router();
itdrRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en ITDR');
  res.status(500).json({ error: 'Error interno del servidor' });
}

itdrRouter.get('/overview', canManage, async (_req, res) => {
  try { res.json(await getOverview()); } catch (e) { handle(e, res); }
});
itdrRouter.get('/findings', canManage, async (req, res) => {
  try {
    res.json({ findings: await listFindings({
      estado: typeof req.query.estado === 'string' ? req.query.estado : undefined,
      tipo: typeof req.query.tipo === 'string' ? req.query.tipo : undefined,
    }) });
  } catch (e) { handle(e, res); }
});
itdrRouter.post('/scan', canManage, async (req, res) => {
  try {
    const r = await scan(typeof req.body?.range === 'string' ? req.body.range : '24h');
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'itdr_scan', target: 'o365', result: 'ok', detail: { viaje: r.viajeImposible, mfa: r.mfaFatigue, nuevos: r.nuevos } });
    res.json(r);
  } catch (e) { handle(e, res); }
});
itdrRouter.put('/findings/:id/status', canManage, async (req, res) => {
  try { await setStatus(req.params.id, typeof req.body?.estado === 'string' ? req.body.estado : ''); res.json({ ok: true }); } catch (e) { handle(e, res); }
});

// Reenvía por Telegram (con explicación + remediación) los hallazgos abiertos.
itdrRouter.post('/notify', canManage, async (req, res) => {
  try {
    const tipo = typeof req.body?.tipo === 'string' ? req.body.tipo : undefined;
    const items = await listFindings({ estado: 'open', tipo });
    if (!items.length) { res.json({ ok: true, sent: 0, message: 'No hay hallazgos abiertos' }); return; }
    if (!env.TELEGRAM_CHAT_ID) { res.status(400).json({ error: 'Telegram no configurado' }); return; }
    await sendTelegram([env.TELEGRAM_CHAT_ID], buildTelegramReport(items), { plain: true });
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'itdr_notify', target: 'telegram', result: 'ok', detail: { enviados: items.length } });
    res.json({ ok: true, sent: items.length });
  } catch (e) { handle(e, res); }
});

/** Scheduler: análisis periódico de identidad + aviso Telegram de hallazgos nuevos. */
export function startItdrScheduler(): void {
  if (!isItdrEnabled()) { logger.info('🪪 ITDR desactivado (ITDR_ENABLED=false)'); return; }
  const spec = env.ITDR_SCAN_CRON || '40 */3 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de ITDR inválido'); return; }
  cron.schedule(spec, async () => {
    try {
      const r = await scan(env.ITDR_RANGE || '24h');
      logger.info({ viaje: r.viajeImposible, mfa: r.mfaFatigue, nuevos: r.nuevos }, '🪪 Análisis ITDR completado');
      if (r.nuevosList.length && env.TELEGRAM_CHAT_ID) {
        await sendTelegram([env.TELEGRAM_CHAT_ID], buildTelegramReport(r.nuevosList), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en análisis ITDR programado'); }
  });
  logger.info(`🪪 ITDR activo (${spec})`);
}
