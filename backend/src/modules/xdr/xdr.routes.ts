/**
 * XDR — grafo de actividad cross-dominio (SmartGrouping). Admin/analista.
 *   GET /api/xdr/groups?range=24h
 *   GET /api/xdr/graph?type=ip|host|user|domain&value=<x>&range=7d
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import { getGroups, getGraph, type EntType } from './xdr.service';

export const xdrRouter = Router();
xdrRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en XDR');
  res.status(500).json({ error: 'Error interno del servidor' });
}

xdrRouter.get('/groups', canManage, async (req, res) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json({ groups: await getGroups(range) });
  } catch (e) { handle(e, res); }
});

xdrRouter.get('/graph', canManage, async (req, res) => {
  try {
    const type = String(req.query.type ?? '') as EntType;
    const value = typeof req.query.value === 'string' ? req.query.value : '';
    const range = typeof req.query.range === 'string' ? req.query.range : '7d';
    res.json(await getGraph(type, value, range));
  } catch (e) { handle(e, res); }
});
