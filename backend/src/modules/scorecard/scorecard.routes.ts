/**
 * Scorecard de Exposición Externa.
 *   GET  /api/scorecard          calificación A–F agregada (cache 5 min)
 *   POST /api/scorecard/refresh  invalida el cache y recalcula (admin/analista)
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { getScorecard, invalidateScorecard } from './scorecard.service';

export const scorecardRouter = Router();
scorecardRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Scorecard');
  res.status(500).json({ error: 'No se pudo construir el scorecard de exposición' });
}

scorecardRouter.get('/', canView, async (_req, res) => {
  try { res.json(await getScorecard()); } catch (e) { fail(e, res); }
});

scorecardRouter.post('/refresh', canView, async (_req, res) => {
  try { invalidateScorecard(); res.json(await getScorecard()); } catch (e) { fail(e, res); }
});
