/**
 * Rutas de metricas de operacion del SOC.
 *   GET /api/metrics/soc?days=30   (admin | analista)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getSocMetrics } from './metrics.service';

export const metricsRouter = Router();
metricsRouter.use(authenticate, requireRole('admin', 'analista'));

metricsRouter.get('/soc', async (req: Request, res: Response) => {
  const days = Math.min(Math.max(Number(req.query.days) || 30, 1), 365);
  try {
    res.json(await getSocMetrics(days));
  } catch {
    res.status(500).json({ error: 'No se pudieron calcular las metricas' });
  }
});
