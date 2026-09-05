/**
 * Rutas del modulo Wazuh (solo lectura). Requieren autenticacion.
 *
 * Indexer (alertas):
 *   GET /api/wazuh/alerts/count?range=24h
 *   GET /api/wazuh/alerts/by-severity?range=24h
 *   GET /api/wazuh/alerts/summary?range=24h
 *   GET /api/wazuh/alerts/timeline?range=24h&interval=1h
 *   GET /api/wazuh/alerts/top-agents?range=24h&size=10
 *   GET /api/wazuh/alerts/mitre?range=24h&size=10
 *
 * Wazuh API (agentes):
 *   GET /api/wazuh/agents/summary
 *   GET /api/wazuh/agents?limit=50
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import {
  countAlerts,
  countBySeverity,
  getSummary,
  getTimeline,
  getTopAgents,
  getMitre,
  searchAlerts,
  getAlertDetail,
} from './wazuh.service';
import { getAgentsSummary, getAgents, getAgentsBySede } from './agents.service';
import { HttpError } from '../auth/auth.service';

export const wazuhRouter = Router();
wazuhRouter.use(authenticate);

// Helper para leer el rango con valor por defecto
const getRange = (req: Request) =>
  typeof req.query.range === 'string' ? req.query.range : '24h';
const getSize = (req: Request, def: number) => {
  const n = Number(req.query.size);
  return Number.isFinite(n) && n > 0 && n <= 50 ? Math.floor(n) : def;
};

// Explorador de alertas: busqueda paginada con filtros
wazuhRouter.get('/alerts/search', async (req: Request, res: Response) => {
  try {
    const str = (k: string) => (typeof req.query[k] === 'string' && req.query[k] ? String(req.query[k]) : undefined);
    const page = Math.max(0, Math.floor(Number(req.query.page) || 0));
    const sizeN = Number(req.query.size);
    const size = Number.isFinite(sizeN) && sizeN > 0 && sizeN <= 100 ? Math.floor(sizeN) : 25;
    res.json(
      await searchAlerts({
        range: getRange(req),
        band: str('band'),
        agent: str('agent'),
        srcip: str('srcip'),
        ruleId: str('ruleId'),
        q: str('q'),
        mitre: str('mitre'),
        user: str('user'),
        triage: req.query.triage === 'true' || req.query.triage === '1',
        page,
        size,
      })
    );
  } catch (err) {
    sendError(err, res);
  }
});

// Documento completo de una alerta (panel de detalle)
wazuhRouter.get('/alerts/detail', async (req: Request, res: Response) => {
  const index = typeof req.query.index === 'string' ? req.query.index : '';
  const id = typeof req.query.id === 'string' ? req.query.id : '';
  if (!index || !id) {
    res.status(400).json({ error: 'Faltan parámetros index/id' });
    return;
  }
  try {
    res.json({ source: await getAlertDetail(index, id) });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/alerts/count', async (req, res) => {
  try {
    const range = getRange(req);
    res.json({ range, count: await countAlerts(range) });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/alerts/by-severity', async (req, res) => {
  try {
    const range = getRange(req);
    res.json({ range, data: await countBySeverity(range) });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/alerts/summary', async (req, res) => {
  try {
    res.json(await getSummary(getRange(req)));
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/alerts/timeline', async (req, res) => {
  try {
    const range = getRange(req);
    const interval =
      typeof req.query.interval === 'string' ? req.query.interval : '1h';
    res.json({ range, interval, data: await getTimeline(range, interval) });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/alerts/top-agents', async (req, res) => {
  try {
    const range = getRange(req);
    res.json({ range, data: await getTopAgents(range, getSize(req, 10)) });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/alerts/mitre', async (req, res) => {
  try {
    const range = getRange(req);
    res.json({ range, data: await getMitre(range, getSize(req, 10)) });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/agents/summary', async (_req, res) => {
  try {
    res.json(await getAgentsSummary());
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/agents/by-sede', async (_req, res) => {
  try {
    res.json({ data: await getAgentsBySede() });
  } catch (err) {
    sendError(err, res);
  }
});

wazuhRouter.get('/agents', async (req, res) => {
  try {
    const n = Number(req.query.limit);
    const limit = Number.isFinite(n) && n > 0 && n <= 500 ? Math.floor(n) : 50;
    res.json({ data: await getAgents(limit) });
  } catch (err) {
    sendError(err, res);
  }
});

function sendError(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Error en wazuh:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
}
