/**
 * Rutas de Analítica de API por endpoint (sobre web-accesslog de Wazuh).
 *   GET /api/api-analytics?range=1h|24h|7d
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getApiAnalytics } from './api-analytics.service';

export const apiAnalyticsRouter = Router();
apiAnalyticsRouter.use(authenticate);

apiAnalyticsRouter.get('/', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getApiAnalytics(range));
  } catch (e) {
    res.status(500).json({ error: (e as Error).message || 'No se pudo generar la analítica de API' });
  }
});
