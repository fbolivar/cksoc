/**
 * Shadow-AI — uso de servicios de IA generativa detectado por red. Admin/analista.
 *   GET    /api/shadow-ai/overview
 *   GET    /api/shadow-ai/usage?shadow=1
 *   GET    /api/shadow-ai/services           (catálogo + política)
 *   POST   /api/shadow-ai/scan
 *   PUT    /api/shadow-ai/policy/:service     { sanctioned }
 *   DELETE /api/shadow-ai/usage/:srcip/:service
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
import { isShadowAiEnabled, scan, getOverview, listUsage, listServices, setPolicy, forget } from './shadowai.service';

export const shadowAiRouter = Router();
shadowAiRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en Shadow-AI');
  res.status(500).json({ error: 'Error interno del servidor' });
}

shadowAiRouter.get('/overview', canManage, async (_req, res) => {
  try { res.json(await getOverview()); } catch (e) { handle(e, res); }
});
shadowAiRouter.get('/usage', canManage, async (req, res) => {
  try { res.json({ usage: await listUsage({ shadow: req.query.shadow === '1' || req.query.shadow === 'true' }) }); } catch (e) { handle(e, res); }
});
shadowAiRouter.get('/services', canManage, async (_req, res) => {
  try { res.json({ services: await listServices() }); } catch (e) { handle(e, res); }
});
shadowAiRouter.post('/scan', canManage, async (req, res) => {
  try {
    const r = await scan(typeof req.body?.range === 'string' ? req.body.range : '7d');
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'shadowai_scan', target: 'red', result: 'ok', detail: { dispositivos: r.devices, servicios: r.services, nuevos: r.nuevos } });
    res.json(r);
  } catch (e) { handle(e, res); }
});
shadowAiRouter.put('/policy/:service', canManage, async (req, res) => {
  try {
    const sanctioned = req.body?.sanctioned === true || req.body?.sanctioned === 'true';
    await setPolicy(req.params.service, sanctioned, req.user?.id ?? null);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'shadowai_policy', target: req.params.service, result: 'ok', detail: { sanctioned } });
    res.json({ ok: true });
  } catch (e) { handle(e, res); }
});
shadowAiRouter.delete('/usage/:srcip/:service', canManage, async (req, res) => {
  try { await forget(req.params.srcip, req.params.service); res.json({ ok: true }); } catch (e) { handle(e, res); }
});

/** Scheduler: escaneo periódico de uso de IA + aviso Telegram de shadow-AI nuevo. */
export function startShadowAiScheduler(): void {
  if (!isShadowAiEnabled()) { logger.info('🤖 Shadow-AI desactivado (SHADOW_AI_ENABLED=false)'); return; }
  const spec = env.SHADOW_AI_SCAN_CRON || '20 5 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de Shadow-AI inválido'); return; }
  cron.schedule(spec, async () => {
    try {
      const r = await scan(env.SHADOW_AI_RANGE || '7d');
      logger.info({ dispositivos: r.devices, servicios: r.services, nuevos: r.nuevos, shadow: r.nuevosShadow.length }, '🤖 Escaneo Shadow-AI completado');
      if (r.nuevosShadow.length && env.TELEGRAM_CHAT_ID) {
        const L = ['🤖 Agentico · Uso de IA no autorizado (Shadow-AI)', '', `Detecté ${r.nuevosShadow.length} nuevo(s) uso(s) de IA generativa NO aprobada desde la red:`, ''];
        for (const s of r.nuevosShadow.slice(0, 12)) L.push(`• ${s.host || s.srcip} → ${s.service}`);
        L.push('', 'Sugiero validar si estas herramientas están permitidas por la política de datos (riesgo de fuga de información sensible). Puedo ayudarte a aprobarlas o restringirlas.');
        await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en escaneo Shadow-AI programado'); }
  });
  logger.info(`🤖 Shadow-AI activo (${spec})`);
}
