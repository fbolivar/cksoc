/**
 * Threat Intelligence: catálogo de IOCs, feeds y cruce contra alertas.
 * Lectura para admin/analista; alta/borrado/refresh también admin/analista.
 */
import { Router, type Request, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import {
  listIocs, countByType, addIoc, removeIoc, getFeeds, refreshFeeds, getMatches,
} from './threatintel.service';

export const threatIntelRouter = Router();
threatIntelRouter.use(authenticate);

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en threat intel');
  res.status(500).json({ error: 'Error interno del servidor' });
}

threatIntelRouter.get('/summary', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json({ ...(await countByType()), feeds: await getFeeds() }); }
  catch (err) { handle(err, res); }
});

threatIntelRouter.get('/iocs', requireRole('admin', 'analista'), async (req, res) => {
  try {
    res.json({ iocs: await listIocs({
      type: typeof req.query.type === 'string' ? req.query.type : undefined,
      q: typeof req.query.q === 'string' ? req.query.q : undefined,
    }) });
  } catch (err) { handle(err, res); }
});

threatIntelRouter.post('/iocs', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const ioc = await addIoc({ type: req.body?.type, value: req.body?.value, description: req.body?.description, tags: req.body?.tags }, req.user!.id);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'ti_ioc_add', target: ioc.value, result: 'ok', detail: { type: ioc.ioc_type } });
    res.status(201).json(ioc);
  } catch (err) { handle(err, res); }
});

threatIntelRouter.delete('/iocs/:id', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    await removeIoc(String(req.params.id));
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'ti_ioc_remove', target: String(req.params.id), result: 'ok' });
    res.json({ ok: true });
  } catch (err) { handle(err, res); }
});

threatIntelRouter.post('/feeds/refresh', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const results = await refreshFeeds();
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'ti_feed_refresh', result: 'ok', detail: { results } });
    res.json({ results });
  } catch (err) { handle(err, res); }
});

threatIntelRouter.get('/matches', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json({ matches: await getMatches() }); }
  catch (err) { handle(err, res); }
});

/** Refresco diario de feeds (03:15). */
export function startThreatIntelScheduler(): void {
  cron.schedule('15 3 * * *', () => {
    refreshFeeds()
      .then((r) => logger.info({ r }, 'Threat Intel: feeds actualizados'))
      .catch((err) => logger.warn({ err: err instanceof Error ? err.message : err }, 'Threat Intel: fallo al actualizar feeds'));
  });
}
