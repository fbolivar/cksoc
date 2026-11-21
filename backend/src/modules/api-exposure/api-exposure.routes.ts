/**
 * Rutas de Exposición de APIs.
 *   GET  /api/api-exposure         -> inventario + hallazgos + shadow/zombie
 *   POST /api/api-exposure/scan    -> dispara un escaneo activo (admin)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getApiExposure, scanApiExposure } from './api-exposure.service';

export const apiExposureRouter = Router();
apiExposureRouter.use(authenticate);

apiExposureRouter.get('/', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try { res.json(await getApiExposure()); }
  catch { res.status(500).json({ error: 'No se pudo cargar la exposición de APIs' }); }
});

apiExposureRouter.post('/scan', requireRole('admin'), async (_req: Request, res: Response) => {
  try { res.json(await scanApiExposure()); }
  catch { res.status(500).json({ error: 'No se pudo ejecutar el escaneo de APIs' }); }
});
