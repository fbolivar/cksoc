/**
 * Flujos de red (analítica NetFlow/QFlow del SonicWall). Admin/analista.
 *   GET /api/flows/overview?range=24h
 *   GET /api/flows/beaconing?range=24h
 *   GET /api/flows/scans?range=24h
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import { getOverview, getBeaconing, getScans } from './flows.service';

export const flowsRouter = Router();
flowsRouter.use(authenticate);
const canRead = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en flujos');
  res.status(500).json({ error: 'Error interno del servidor' });
}
const rng = (v: unknown): string => (typeof v === 'string' ? v : '24h');

flowsRouter.get('/overview', canRead, async (req, res) => { try { res.json(await getOverview(rng(req.query.range))); } catch (e) { handle(e, res); } });
flowsRouter.get('/beaconing', canRead, async (req, res) => { try { res.json({ beacons: await getBeaconing(rng(req.query.range)) }); } catch (e) { handle(e, res); } });
flowsRouter.get('/scans', canRead, async (req, res) => { try { res.json({ scans: await getScans(rng(req.query.range)) }); } catch (e) { handle(e, res); } });
