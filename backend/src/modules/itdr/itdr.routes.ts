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
import { isItdrEnabled, scan, getOverview, listFindings, setStatus } from './itdr.service';

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
        const L = ['🪪 Agentico · Amenazas de identidad (ITDR)', '', `Detecté ${r.nuevosList.length} señal(es) nueva(s) en los inicios de sesión de Microsoft 365:`, ''];
        for (const f of r.nuevosList.slice(0, 12)) L.push(`• [${String(f.severidad).toUpperCase()}] ${f.usuario} — ${f.detalle}`);
        L.push('', 'Recomiendo verificar con la persona y, si aplica, forzar cambio de contraseña + revocar sesiones. Puedo apoyar en la contención.');
        await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en análisis ITDR programado'); }
  });
  logger.info(`🪪 ITDR activo (${spec})`);
}
