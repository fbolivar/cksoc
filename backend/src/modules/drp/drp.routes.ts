/**
 * DRP — Digital Risk Protection (typosquatting + CT + credenciales). Admin/analista.
 *   GET  /api/drp/overview
 *   GET  /api/drp/findings?estado=&tipo=
 *   POST /api/drp/scan
 *   PUT  /api/drp/findings/:id/status { estado }
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
import { isDrpEnabled, scan, getOverview, listFindings, setStatus } from './drp.service';

export const drpRouter = Router();
drpRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en DRP');
  res.status(500).json({ error: 'Error interno del servidor' });
}

drpRouter.get('/overview', canManage, async (_req, res) => {
  try { res.json(await getOverview()); } catch (e) { handle(e, res); }
});
drpRouter.get('/findings', canManage, async (req, res) => {
  try {
    res.json({ findings: await listFindings({
      estado: typeof req.query.estado === 'string' ? req.query.estado : undefined,
      tipo: typeof req.query.tipo === 'string' ? req.query.tipo : undefined,
    }) });
  } catch (e) { handle(e, res); }
});
drpRouter.post('/scan', canManage, async (req, res) => {
  try {
    const r = await scan();
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'drp_scan', target: 'marcas', result: 'ok', detail: { registrados: r.registrados, certs: r.certs, nuevos: r.nuevos } });
    res.json(r);
  } catch (e) { handle(e, res); }
});
drpRouter.put('/findings/:id/status', canManage, async (req, res) => {
  try { await setStatus(req.params.id, typeof req.body?.estado === 'string' ? req.body.estado : ''); res.json({ ok: true }); } catch (e) { handle(e, res); }
});

/** Scheduler: barrido diario de riesgo digital + aviso Telegram de dominios nuevos. */
export function startDrpScheduler(): void {
  if (!isDrpEnabled()) { logger.info('🕵️ DRP desactivado (DRP_ENABLED=false)'); return; }
  const spec = env.DRP_SCAN_CRON || '10 5 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de DRP inválido'); return; }
  cron.schedule(spec, async () => {
    try {
      const r = await scan();
      logger.info({ registrados: r.registrados, certs: r.certs, nuevos: r.nuevos }, '🕵️ Barrido DRP completado');
      const criticos = r.nuevosList.filter((f) => f.severidad !== 'media');
      if (criticos.length && env.TELEGRAM_CHAT_ID) {
        const L = ['🕵️ Agentico · Riesgo digital (DRP) — dominios que suplantan la marca', '', `Detecté ${criticos.length} dominio(s) nuevo(s) parecido(s) al del cliente, activos y potencialmente para phishing:`, ''];
        for (const f of criticos.slice(0, 12)) L.push(`• [${String(f.severidad).toUpperCase()}] ${f.detalle}`);
        L.push('', 'Recomiendo: reportar el dominio para takedown (registrador/hosting), avisar a los usuarios y, si tiene MX, vigilar correos entrantes que lo referencien. Puedo ayudar con el reporte.');
        await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en barrido DRP programado'); }
  });
  logger.info(`🕵️ DRP activo (${spec})`);
}
