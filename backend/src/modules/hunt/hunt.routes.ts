/**
 * Rutas de Threat Hunting (admin | analista).
 *   GET /api/hunt?range=24h&q=&agent=&ruleId=&minLevel=&srcip=&mitre=&size=&page=
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { hunt } from './hunt.service';

export const huntRouter = Router();
huntRouter.use(authenticate, requireRole('admin', 'analista'));

const s = (req: Request, k: string): string | undefined =>
  typeof req.query[k] === 'string' && req.query[k] ? String(req.query[k]) : undefined;

huntRouter.get('/', async (req: Request, res: Response) => {
  try {
    const result = await hunt({
      range: s(req, 'range'),
      from: s(req, 'from'),
      to: s(req, 'to'),
      q: s(req, 'q'),
      agent: s(req, 'agent'),
      ruleId: s(req, 'ruleId'),
      minLevel: req.query.minLevel ? Number(req.query.minLevel) : undefined,
      srcip: s(req, 'srcip'),
      mitre: s(req, 'mitre'),
      size: req.query.size ? Number(req.query.size) : undefined,
      page: req.query.page ? Number(req.query.page) : undefined,
    });
    res.json(result);
  } catch {
    res.status(502).json({ error: 'No se pudo consultar el indice de alertas (Wazuh Indexer)' });
  }
});
