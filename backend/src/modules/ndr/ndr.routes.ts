/**
 * NDR (visibilidad de red vía FortiGate).
 *   GET /api/ndr?range=1h|24h|7d
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getNdrOverview, getVpnSessions, getUserActivity } from './ndr.service';

export const ndrRouter = Router();
ndrRouter.use(authenticate);

ndrRouter.get('/', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getNdrOverview(range));
  } catch {
    res.status(500).json({ error: 'No se pudo construir la vista de red (NDR)' });
  }
});

/** Sesiones VPN activas en tiempo real (usuario/grupo/bytes). */
ndrRouter.get('/vpn', async (_req: Request, res: Response) => {
  try { res.json(await getVpnSessions()); }
  catch (e) { res.status(502).json({ error: e instanceof Error ? e.message : 'No se pudieron leer las sesiones VPN' }); }
});

/** Actividad en Internet por equipo, clasificada por categoría + riesgo. */
ndrRouter.get('/user-activity', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getUserActivity(range));
  } catch {
    res.status(500).json({ error: 'No se pudo construir la actividad por equipo' });
  }
});
