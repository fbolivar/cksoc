/**
 * Dashboard Office 365.
 *   GET /api/office365?range=24h|7d|30d
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getO365Overview } from './o365.service';

export const office365Router = Router();
office365Router.use(authenticate);

office365Router.get('/', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getO365Overview(range));
  } catch {
    res.status(500).json({ error: 'No se pudo construir el dashboard de Office 365' });
  }
});
