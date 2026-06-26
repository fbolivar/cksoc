/**
 * Rutas de MITRE ATT&CK.
 *   GET /api/mitre?hours=168
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getMitre } from './mitre.service';
import { HttpError } from '../auth/auth.service';

export const mitreRouter = Router();
mitreRouter.use(authenticate);

mitreRouter.get('/', async (req: Request, res: Response) => {
  const h = Number(req.query.hours);
  const hours = Number.isFinite(h) && h > 0 && h <= 720 ? Math.floor(h) : 168;
  try {
    res.json(await getMitre(hours));
  } catch (err) {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Error interno consultando MITRE ATT&CK' });
  }
});
