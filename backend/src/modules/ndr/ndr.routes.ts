/**
 * NDR (visibilidad de red vía FortiGate).
 *   GET /api/ndr?range=1h|24h|7d
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getNdrOverview } from './ndr.service';

export const ndrRouter = Router();
ndrRouter.use(authenticate);

ndrRouter.get('/', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getNdrOverview(range));
  } catch {
    res.status(500).json({ error: 'No se pudo construir la vista de red (NDR)' });
  }
});
