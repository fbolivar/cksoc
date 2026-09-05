/**
 * Monitoreo de exposicion de credenciales (HIBP Domain). Admin/analista.
 *   GET    /api/credential-exposure/summary
 *   GET    /api/credential-exposure/accounts?domain=&estado=&q=
 *   POST   /api/credential-exposure/domains        { domain }
 *   DELETE /api/credential-exposure/domains/:domain
 *   POST   /api/credential-exposure/scan           (escanea todos)
 *   POST   /api/credential-exposure/scan/:domain
 *   PUT    /api/credential-exposure/accounts/:id/status  { estado }
 */
import { Router, type Request, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import {
  getSummary, listAccounts, addDomain, removeDomain, scanAll, scanDomain,
  setStatus, refreshBreachCatalog, isHibpConfigured, hibpDiagnostics,
} from './credexp.service';

export const credExpRouter = Router();
credExpRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en exposicion de credenciales');
  res.status(500).json({ error: 'Error interno del servidor' });
}

credExpRouter.get('/summary', canManage, async (_req, res) => {
  try { res.json(await getSummary()); } catch (err) { handle(err, res); }
});

// Diagnóstico de prerequisitos en vivo (clave válida, plan, dominios registrados en HIBP).
credExpRouter.get('/diagnostics', canManage, async (_req, res) => {
  try { res.json(await hibpDiagnostics()); } catch (err) { handle(err, res); }
});

credExpRouter.get('/accounts', canManage, async (req, res) => {
  try {
    res.json({ accounts: await listAccounts({
      domain: typeof req.query.domain === 'string' ? req.query.domain : undefined,
      estado: typeof req.query.estado === 'string' ? req.query.estado : undefined,
      q: typeof req.query.q === 'string' ? req.query.q : undefined,
    }) });
  } catch (err) { handle(err, res); }
});

credExpRouter.post('/domains', canManage, async (req: Request, res: Response) => {
  try {
    const domain = typeof req.body?.domain === 'string' ? req.body.domain : '';
    const d = await addDomain(domain);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'credexp_domain_add', target: d.domain, result: 'ok' });
    res.status(201).json({ domain: d });
  } catch (err) { handle(err, res); }
});

credExpRouter.delete('/domains/:domain', canManage, async (req, res) => {
  try {
    await removeDomain(req.params.domain);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'credexp_domain_remove', target: req.params.domain, result: 'ok' });
    res.json({ ok: true });
  } catch (err) { handle(err, res); }
});

credExpRouter.post('/scan', canManage, async (req, res) => {
  try {
    const out = await scanAll();
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'credexp_scan_all', target: 'todos', result: 'ok', detail: { dominios: out.length } });
    res.json({ resultados: out });
  } catch (err) { handle(err, res); }
});

credExpRouter.post('/scan/:domain', canManage, async (req, res) => {
  try {
    const r = await scanDomain(req.params.domain);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'credexp_scan_domain', target: req.params.domain, result: 'ok', detail: r });
    res.json(r);
  } catch (err) { handle(err, res); }
});

credExpRouter.put('/accounts/:id/status', canManage, async (req, res) => {
  try {
    const estado = req.body?.estado;
    await setStatus(req.params.id, estado, req.user?.id ?? null);
    res.json({ ok: true });
  } catch (err) { handle(err, res); }
});

/** Scheduler diario: refresca catalogo de brechas y escanea los dominios. */
export function startCredExpScheduler(): void {
  if (!isHibpConfigured()) {
    logger.info('🔓 Monitoreo de credenciales inactivo (falta HIBP_API_KEY)');
    return;
  }
  if (!cron.validate(env.HIBP_SCAN_CRON)) {
    logger.error({ cron: env.HIBP_SCAN_CRON }, 'Cron de HIBP inválido');
    return;
  }
  cron.schedule(env.HIBP_SCAN_CRON, async () => {
    try {
      await refreshBreachCatalog().catch(() => 0);
      const out = await scanAll();
      const nuevas = out.reduce((s, x) => s + x.nuevas, 0);
      logger.info({ dominios: out.length, nuevas }, '🔓 Escaneo de credenciales completado');
    } catch (e) {
      logger.error({ err: e }, 'Error en escaneo programado de credenciales');
    }
  });
  logger.info(`🔓 Monitoreo de credenciales activo (${env.HIBP_SCAN_CRON})`);
}
