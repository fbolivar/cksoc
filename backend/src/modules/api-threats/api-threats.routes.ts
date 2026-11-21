/**
 * Rutas de Amenazas de API — scorecard OWASP API Security Top 10.
 *   GET /api/api-threats?range=1h|24h|7d  -> { resumen, categorias }
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getApiThreats } from './api-threats.service';

export const apiThreatsRouter = Router();
apiThreatsRouter.use(authenticate);

apiThreatsRouter.get('/', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    const report = await getApiThreats(range);
    res.json(report);
  } catch (e) {
    res.status(500).json({ error: (e as Error).message || 'No se pudo generar el scorecard de API' });
  }
});
