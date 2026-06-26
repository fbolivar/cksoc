/**
 * Rutas de Configuration Assessment (SCA).
 *   GET /api/sca   postura de hardening por agente + top checks fallidos
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getSca } from './sca.service';
import { HttpError } from '../auth/auth.service';

export const scaRouter = Router();
scaRouter.use(authenticate);

scaRouter.get('/', async (_req: Request, res: Response) => {
  try {
    res.json(await getSca());
  } catch (err) {
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: 'Error interno consultando SCA' });
  }
});
