/**
 * Rutas del Risk-Based Alerting (riesgo acumulado por entidad).
 *   GET /api/entity-risk?range=24h|7d|30d   -> { hosts, users }
 *   GET /api/entity-risk/triage?limit=N      -> top-N combinado (widget)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getEntityRisk, getTriagePriority } from './entity-risk.service';

export const entityRiskRouter = Router();
entityRiskRouter.use(authenticate);

entityRiskRouter.get('/', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getEntityRisk(range));
  } catch {
    res.status(500).json({ error: 'No se pudo calcular el riesgo por entidad' });
  }
});

entityRiskRouter.get('/triage', async (req: Request, res: Response) => {
  try {
    const limit = Math.min(20, Math.max(1, Number(req.query.limit) || 6));
    res.json({ items: await getTriagePriority(limit) });
  } catch {
    res.status(500).json({ error: 'No se pudo calcular la prioridad de triage' });
  }
});
