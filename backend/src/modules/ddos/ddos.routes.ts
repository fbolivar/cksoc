/**
 * Rutas de Detección DDoS / Bots (sobre flujos del SonicWall).
 *   GET /api/ddos?range=1h|24h|7d  -> { volumetric, bots, resumen }
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getDdosBots } from './ddos.service';

export const ddosRouter = Router();
ddosRouter.use(authenticate);

ddosRouter.get('/', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const range = typeof req.query.range === 'string' ? req.query.range : '24h';
  try { res.json(await getDdosBots(range)); }
  catch { res.status(500).json({ error: 'No se pudo calcular la detección DDoS/bots' }); }
});
