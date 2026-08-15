/**
 * Ruta del Resumen Ejecutivo consolidado.
 *   GET /api/overview
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getOverview } from './overview.service';
import { getAssetRadar } from './radar.service';
import { getSedes } from './sedes.service';

export const overviewRouter = Router();
overviewRouter.use(authenticate);

overviewRouter.get('/', async (_req: Request, res: Response) => {
  try {
    res.json(await getOverview());
  } catch {
    res.status(500).json({ error: 'No se pudo construir el resumen ejecutivo' });
  }
});

overviewRouter.get('/radar', async (_req: Request, res: Response) => {
  try {
    res.json(await getAssetRadar());
  } catch {
    res.status(500).json({ error: 'No se pudo construir el radar de activos' });
  }
});

overviewRouter.get('/sedes', async (_req: Request, res: Response) => {
  try {
    res.json({ sedes: await getSedes() });
  } catch {
    res.status(500).json({ error: 'No se pudieron construir las métricas por sede' });
  }
});
