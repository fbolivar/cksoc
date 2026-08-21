/**
 * Dashboard Office 365.
 *   GET /api/office365?range=24h|7d|30d
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getO365Overview } from './o365.service';
import { listM365Identities } from '../identity/identity.service';

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

// Directorio de identidades del tenant vía Microsoft Graph (solo lectura).
office365Router.get('/identities', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try {
    res.json(await listM365Identities());
  } catch (e) {
    const status = (e as { status?: number }).status ?? 502;
    res.status(status).json({ error: (e as { message?: string }).message ?? 'No se pudo consultar el directorio M365' });
  }
});
