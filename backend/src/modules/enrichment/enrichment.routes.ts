/**
 * Enriquecimiento de IPs.
 *   GET /api/enrichment/ip/:ip  -> { verdict, geo, reputation, ioc, alerts24h }
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { enrichIp } from './enrichment.service';

export const enrichmentRouter = Router();
enrichmentRouter.use(authenticate);

const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;

enrichmentRouter.get('/ip/:ip', async (req: Request, res: Response) => {
  const ip = String(req.params.ip || '').trim();
  if (!IP_RE.test(ip)) { res.status(400).json({ error: 'IP inválida' }); return; }
  try {
    res.json(await enrichIp(ip));
  } catch {
    res.status(500).json({ error: 'No se pudo enriquecer la IP' });
  }
});
