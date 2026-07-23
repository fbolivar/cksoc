/** Ruta del Tablero Ejecutivo de Riesgo (solo admin).
 *   GET /api/risk/board
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getRiskBoard } from './risk.service';

export const riskRouter = Router();
riskRouter.use(authenticate, requireRole('admin'));

let cache: { at: number; data: unknown } | null = null;
const TTL = 60_000; // el tablero agrega varias fuentes; cache de 1 min

riskRouter.get('/board', async (_req: Request, res: Response) => {
  try {
    if (cache && Date.now() - cache.at < TTL) {
      res.json(cache.data);
      return;
    }
    const data = await getRiskBoard();
    cache = { at: Date.now(), data };
    res.json(data);
  } catch {
    res.status(500).json({ error: 'No se pudo calcular el tablero de riesgo' });
  }
});
