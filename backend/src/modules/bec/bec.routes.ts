/**
 * Anti-BEC (correo) — señales de compromiso de correo. Admin/analista.
 *   GET    /api/bec/overview
 *   GET    /api/bec/findings?estado=&tipo=
 *   POST   /api/bec/scan               { range }
 *   POST   /api/bec/notify             (reenvía abiertos a Telegram)
 *   PUT    /api/bec/findings/:id/status { estado }
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
import { isBecEnabled, scan, getOverview, listFindings, setStatus, buildTelegramReport } from './bec.service';

export const becRouter = Router();
becRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en anti-BEC');
  res.status(500).json({ error: 'Error interno del servidor' });
}

becRouter.get('/overview', canManage, async (_req, res) => {
  try { res.json(await getOverview()); } catch (e) { handle(e, res); }
});
becRouter.get('/findings', canManage, async (req, res) => {
  try {
    res.json({ findings: await listFindings({
      estado: typeof req.query.estado === 'string' ? req.query.estado : undefined,
      tipo: typeof req.query.tipo === 'string' ? req.query.tipo : undefined,
    }) });
  } catch (e) { handle(e, res); }
});
becRouter.post('/scan', canManage, async (req, res) => {
  try {
    const r = await scan(typeof req.body?.range === 'string' ? req.body.range : '7d');
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'bec_scan', target: 'o365', result: 'ok', detail: { reglas: r.reglas, correo: r.correoRevisado, nuevos: r.nuevos } });
    res.json(r);
  } catch (e) { handle(e, res); }
});
becRouter.post('/notify', canManage, async (req, res) => {
  try {
    const tipo = typeof req.body?.tipo === 'string' ? req.body.tipo : undefined;
    const items = await listFindings({ estado: 'open', tipo });
    if (!items.length) { res.json({ ok: true, sent: 0, message: 'No hay hallazgos abiertos' }); return; }
    if (!env.TELEGRAM_CHAT_ID) { res.status(400).json({ error: 'Telegram no configurado' }); return; }
    await sendTelegram([env.TELEGRAM_CHAT_ID], buildTelegramReport(items), { plain: true });
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'bec_notify', target: 'telegram', result: 'ok', detail: { enviados: items.length } });
    res.json({ ok: true, sent: items.length });
  } catch (e) { handle(e, res); }
});
becRouter.put('/findings/:id/status', canManage, async (req, res) => {
  try { await setStatus(req.params.id, typeof req.body?.estado === 'string' ? req.body.estado : ''); res.json({ ok: true }); } catch (e) { handle(e, res); }
});

/** Scheduler: análisis periódico anti-BEC + aviso Telegram (explicación + remediación). */
export function startBecScheduler(): void {
  if (!isBecEnabled()) { logger.info('📧 Anti-BEC desactivado (BEC_ENABLED=false)'); return; }
  const spec = env.BEC_SCAN_CRON || '50 */6 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de anti-BEC inválido'); return; }
  cron.schedule(spec, async () => {
    try {
      const r = await scan(env.BEC_AUDIT_RANGE || '7d');
      logger.info({ reglas: r.reglas, correo: r.correoRevisado, nuevos: r.nuevos }, '📧 Análisis anti-BEC completado');
      if (r.nuevosList.length && env.TELEGRAM_CHAT_ID) {
        await sendTelegram([env.TELEGRAM_CHAT_ID], buildTelegramReport(r.nuevosList), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en análisis anti-BEC programado'); }
  });
  logger.info(`📧 Anti-BEC activo (${spec})`);
}
