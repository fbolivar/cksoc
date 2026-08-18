/**
 * Ruta del Resumen Ejecutivo consolidado.
 *   GET /api/overview
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getOverview } from './overview.service';
import { getAssetRadar } from './radar.service';
import { getSedes } from './sedes.service';
import { getAlertTrend, getPulse } from './pulse.service';

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

overviewRouter.get('/trend', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '7d';
    res.json(await getAlertTrend(range));
  } catch {
    res.status(500).json({ error: 'No se pudo construir la tendencia' });
  }
});

overviewRouter.get('/pulse', async (_req: Request, res: Response) => {
  try {
    res.json(await getPulse());
  } catch {
    res.status(500).json({ error: 'No se pudo construir el pulso del SIEM' });
  }
});
