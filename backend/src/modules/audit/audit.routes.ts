/**
 * Rutas del registro de auditoria (solo admin).
 *   GET /api/audit          lista con filtros + paginacion
 *   GET /api/audit/actions  acciones distintas (para el filtro del frontend)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { listAudit, auditActions } from './audit.service';

export const auditRouter = Router();
auditRouter.use(authenticate, requireRole('admin'));

const str = (req: Request, k: string): string | undefined =>
  typeof req.query[k] === 'string' && req.query[k] ? String(req.query[k]) : undefined;
const num = (req: Request, k: string): number | undefined => {
  const v = Number(req.query[k]);
  return Number.isFinite(v) ? v : undefined;
};

auditRouter.get('/', async (req: Request, res: Response) => {
  try {
    const data = await listAudit({
      action: str(req, 'action'),
      actorEmail: str(req, 'actor'),
      result: str(req, 'result'),
      from: str(req, 'from'),
      to: str(req, 'to'),
      q: str(req, 'q'),
      sensitiveOnly: str(req, 'sensitive') === '1',
      limit: num(req, 'limit'),
      offset: num(req, 'offset'),
    });
    res.json(data);
  } catch {
    res.status(500).json({ error: 'No se pudo cargar la auditoria' });
  }
});

auditRouter.get('/actions', async (_req: Request, res: Response) => {
  try {
    res.json({ actions: await auditActions() });
  } catch {
    res.status(500).json({ error: 'No se pudieron cargar las acciones' });
  }
});
