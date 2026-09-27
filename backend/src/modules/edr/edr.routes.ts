/**
 * EDR / NGAV — conector a Defender/SentinelOne (on-demand).
 *   GET  /api/edr/status
 *   GET  /api/edr/overview
 *   GET  /api/edr/alerts
 *   GET  /api/edr/devices
 *   POST /api/edr/devices/:id/isolate | /unisolate | /scan   (solo admin)
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import { getStatus, getOverview, getAlerts, getDevices, isolate, unisolate, scan } from './edr.service';

export const edrRouter = Router();
edrRouter.use(authenticate);
const canRead = requireRole('admin', 'analista');
const canAct = requireRole('admin');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en EDR');
  res.status(500).json({ error: 'Error interno del servidor' });
}

edrRouter.get('/status', canRead, async (_req, res) => { try { res.json(await getStatus()); } catch (e) { handle(e, res); } });
edrRouter.get('/overview', canRead, async (_req, res) => { try { res.json(await getOverview()); } catch (e) { handle(e, res); } });
edrRouter.get('/alerts', canRead, async (_req, res) => { try { res.json({ alerts: await getAlerts() }); } catch (e) { handle(e, res); } });
edrRouter.get('/devices', canRead, async (_req, res) => { try { res.json({ devices: await getDevices() }); } catch (e) { handle(e, res); } });

for (const [path, fn, action] of [['isolate', isolate, 'edr_isolate'], ['unisolate', unisolate, 'edr_unisolate'], ['scan', scan, 'edr_scan']] as const) {
  edrRouter.post(`/devices/:id/${path}`, canAct, async (req, res) => {
    try {
      await fn(req.params.id);
      void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action, target: req.params.id, result: 'ok' });
      res.json({ ok: true });
    } catch (e) { handle(e, res); }
  });
}
