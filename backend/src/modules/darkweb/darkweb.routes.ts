/**
 * Dark Web Radar (centro de fugas).
 *   GET  /api/darkweb          radar agregado (cache 5 min)
 *   POST /api/darkweb/refresh  recalcula (admin/analista)
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { getRadar, invalidateRadar } from './darkweb.service';

export const darkwebRouter = Router();
darkwebRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Dark Web Radar');
  res.status(500).json({ error: 'No se pudo construir el radar de fugas' });
}

darkwebRouter.get('/', canView, async (_req, res) => {
  try { res.json(await getRadar()); } catch (e) { fail(e, res); }
});
darkwebRouter.post('/refresh', canView, async (_req, res) => {
  try { invalidateRadar(); res.json(await getRadar(true)); } catch (e) { fail(e, res); }
});
