/**
 * Rutas de Deteccion de Vulnerabilidades.
 *   GET /api/vulnerabilities   resumen + top CVE + por agente + lista
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getVulnerabilities } from './vuln.service';
import { HttpError } from '../auth/auth.service';

export const vulnRouter = Router();
vulnRouter.use(authenticate);

vulnRouter.get('/', async (_req: Request, res: Response) => {
  try {
    res.json(await getVulnerabilities());
  } catch (err) {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Error interno consultando vulnerabilidades' });
  }
});
