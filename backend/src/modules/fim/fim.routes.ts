/**
 * Rutas de File Integrity Monitoring (FIM).
 *   GET /api/fim?hours=168
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getFim } from './fim.service';
import { HttpError } from '../auth/auth.service';

export const fimRouter = Router();
fimRouter.use(authenticate);

fimRouter.get('/', async (req: Request, res: Response) => {
  const h = Number(req.query.hours);
  const hours = Number.isFinite(h) && h > 0 && h <= 720 ? Math.floor(h) : 168;
  const signalOnly = req.query.signal !== '0'; // lente "solo señal" por defecto; ?signal=0 = ver todo
  try {
    res.json(await getFim(hours, signalOnly));
  } catch (err) {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Error interno consultando FIM' });
  }
});
