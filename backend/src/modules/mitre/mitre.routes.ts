/**
 * Rutas de MITRE ATT&CK.
 *   GET /api/mitre?hours=168
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getMitre, getCoverage } from './mitre.service';
import { HttpError } from '../auth/auth.service';

export const mitreRouter = Router();
mitreRouter.use(authenticate);

// Cobertura de detección: técnicas detectadas vs. marco ATT&CK, por táctica.
mitreRouter.get('/coverage', async (req: Request, res: Response) => {
  const d = Number(req.query.days);
  const days = Number.isFinite(d) && d > 0 && d <= 365 ? Math.floor(d) : 90;
  try {
    res.json(await getCoverage(days));
  } catch (err) {
    if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
    res.status(500).json({ error: 'Error consultando la cobertura MITRE' });
  }
});

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
