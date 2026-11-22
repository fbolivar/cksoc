/**
 * Generador de Takedown.
 *   GET  /api/takedown/candidates   dominios de suplantación (del DRP) candidatos a retiro
 *   POST /api/takedown/generate     { domain } -> paquete de solicitud (NO envía)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { getCandidates, generatePackage } from './takedown.service';

export const takedownRouter = Router();
takedownRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Takedown');
  res.status(500).json({ error: 'No se pudo procesar la solicitud de takedown' });
}

takedownRouter.get('/candidates', canManage, async (_req, res) => {
  try { res.json(await getCandidates()); } catch (e) { fail(e, res); }
});

takedownRouter.post('/generate', canManage, async (req: Request, res: Response) => {
  try {
    const domain = String(req.body?.domain ?? '').trim();
    if (!domain) { res.status(400).json({ error: 'domain requerido' }); return; }
    res.json(await generatePackage(domain));
  } catch (e) { fail(e, res); }
});
