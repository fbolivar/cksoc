/**
 * Rutas de Cumplimiento normativo.
 *   GET /api/compliance?hours=720
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getCompliance } from './compliance.service';
import { HttpError } from '../auth/auth.service';

export const complianceRouter = Router();
complianceRouter.use(authenticate);

complianceRouter.get('/', async (req: Request, res: Response) => {
  const h = Number(req.query.hours);
  const hours = Number.isFinite(h) && h > 0 && h <= 2160 ? Math.floor(h) : 720;
  try {
    res.json(await getCompliance(hours));
  } catch (err) {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Error interno consultando cumplimiento' });
  }
});
