/**
 * ASM — Attack Surface Management externo. Admin/analista.
 *   GET    /api/asm/overview
 *   GET    /api/asm/assets?domain=
 *   GET    /api/asm/findings?estado=&severidad=
 *   GET    /api/asm/domains
 *   POST   /api/asm/domains             { domain }
 *   DELETE /api/asm/domains/:domain
 *   POST   /api/asm/scan                (todos los dominios)
 *   POST   /api/asm/scan/:domain
 *   PUT    /api/asm/findings/:id/status { estado }
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
import {
  isAsmEnabled, getOverview, listAssets, listFindings, setFindingStatus,
  listDomains, addDomain, removeDomain, scanAll, scanDomain,
} from './asm.service';

export const asmRouter = Router();
asmRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en ASM');
  res.status(500).json({ error: 'Error interno del servidor' });
}

asmRouter.get('/overview', canManage, async (_req, res) => {
  try { res.json(await getOverview()); } catch (e) { handle(e, res); }
});

asmRouter.get('/assets', canManage, async (req, res) => {
  try { res.json({ assets: await listAssets(typeof req.query.domain === 'string' ? req.query.domain : undefined) }); } catch (e) { handle(e, res); }
});

asmRouter.get('/findings', canManage, async (req, res) => {
  try {
    res.json({ findings: await listFindings({
      estado: typeof req.query.estado === 'string' ? req.query.estado : undefined,
      severidad: typeof req.query.severidad === 'string' ? req.query.severidad : undefined,
    }) });
  } catch (e) { handle(e, res); }
});

asmRouter.get('/domains', canManage, async (_req, res) => {
  try { res.json({ domains: await listDomains() }); } catch (e) { handle(e, res); }
});

asmRouter.post('/domains', canManage, async (req, res) => {
  try {
    const d = await addDomain(typeof req.body?.domain === 'string' ? req.body.domain : '');
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'asm_domain_add', target: d.domain, result: 'ok' });
    res.status(201).json({ domain: d });
  } catch (e) { handle(e, res); }
});

asmRouter.delete('/domains/:domain', canManage, async (req, res) => {
  try {
    await removeDomain(req.params.domain);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'asm_domain_remove', target: req.params.domain, result: 'ok' });
    res.json({ ok: true });
  } catch (e) { handle(e, res); }
});

asmRouter.post('/scan', canManage, async (req, res) => {
  try {
    const out = await scanAll();
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'asm_scan_all', target: 'todos', result: 'ok', detail: { dominios: out.length } });
    res.json({ resultados: out });
  } catch (e) { handle(e, res); }
});

asmRouter.post('/scan/:domain', canManage, async (req, res) => {
  try {
    const r = await scanDomain(req.params.domain);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'asm_scan_domain', target: req.params.domain, result: 'ok', detail: { hosts: r.hosts, nuevos: r.nuevos } });
    res.json(r);
  } catch (e) { handle(e, res); }
});

asmRouter.put('/findings/:id/status', canManage, async (req, res) => {
  try {
    await setFindingStatus(req.params.id, typeof req.body?.estado === 'string' ? req.body.estado : '');
    res.json({ ok: true });
  } catch (e) { handle(e, res); }
});

/** Scheduler: escaneo periódico de la superficie externa + aviso Telegram de hallazgos críticos/altos nuevos. */
export function startAsmScheduler(): void {
  if (!isAsmEnabled()) { logger.info('🌐 ASM externo desactivado (ASM_ENABLED=false)'); return; }
  const spec = env.ASM_SCAN_CRON || '30 4 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de ASM inválido'); return; }
  cron.schedule(spec, async () => {
    try {
      const out = await scanAll();
      const nuevos = out.flatMap((r) => r.nuevosList).filter((f) => f.severidad === 'critica' || f.severidad === 'alta');
      const total = out.reduce((s, r) => s + r.nuevos, 0);
      logger.info({ dominios: out.length, nuevos: total }, '🌐 Escaneo ASM completado');
      if (nuevos.length && env.TELEGRAM_CHAT_ID) {
        const L = ['🌐 Agentico · Superficie de ataque externa', '', `Al revisar lo que la organización expone a Internet detecté ${nuevos.length} exposición(es) nueva(s) de riesgo alto/crítico:`, ''];
        for (const f of nuevos.slice(0, 12)) L.push(`• [${String(f.severidad).toUpperCase()}] ${f.host} — ${f.detalle}`);
        L.push('', 'Recomiendo verificar si estas exposiciones son intencionales. Quedo atento para apoyar en la revisión.');
        await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en escaneo ASM programado'); }
  });
  logger.info(`🌐 ASM externo activo (${spec})`);
}
