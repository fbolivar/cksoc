/**
 * Rutas de IT Hygiene (inventario de endpoints).
 *   GET /api/hygiene/summary | /ports | /software | /users | /hotfixes
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getSummary, getPorts, getSoftware, getUsers, getHotfixes } from './hygiene.service';

export const hygieneRouter = Router();
hygieneRouter.use(authenticate);

const wrap = (fn: () => Promise<unknown>) => async (_req: Request, res: Response) => {
  try {
    res.json(await fn());
  } catch {
    res.status(502).json({ error: 'No se pudo consultar el inventario' });
  }
};

hygieneRouter.get('/summary', wrap(getSummary));
hygieneRouter.get('/ports', wrap(getPorts));
hygieneRouter.get('/software', wrap(getSoftware));
hygieneRouter.get('/users', wrap(getUsers));
hygieneRouter.get('/hotfixes', wrap(getHotfixes));
