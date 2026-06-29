/**
 * Rutas de Asset 360.
 *   GET /api/assets          lista de activos
 *   GET /api/assets/:name    detalle consolidado de un activo
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getAssetList, getAsset } from './assets.service';

export const assetsRouter = Router();
assetsRouter.use(authenticate);

assetsRouter.get('/', async (_req: Request, res: Response) => {
  try {
    res.json({ assets: await getAssetList() });
  } catch {
    res.status(502).json({ error: 'No se pudo listar los activos' });
  }
});

assetsRouter.get('/:name', async (req: Request, res: Response) => {
  try {
    const asset = await getAsset(req.params.name);
    if (!asset) {
      res.status(404).json({ error: 'Activo no encontrado' });
      return;
    }
    res.json(asset);
  } catch {
    res.status(502).json({ error: 'No se pudo cargar el activo' });
  }
});
