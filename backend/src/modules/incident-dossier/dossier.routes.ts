/**
 * Rutas del Dossier de Incidente con IA.
 *   POST /api/dossier/generate      { type, value, range?, force? }  -> Dossier
 *   POST /api/dossier/incident/:id  { force? }                        -> Dossier
 *   GET  /api/dossier/recent                                          -> { items }
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { HttpError } from '../auth/auth.service';
import { generateDossier, generateForIncident, listRecentDossiers } from './dossier.service';
import type { EntType } from '../xdr/xdr.service';

export const dossierRouter = Router();
dossierRouter.use(authenticate);

const analystPlus = requireRole('admin', 'analista');

function handle(e: unknown, res: Response): void {
  if (e instanceof HttpError) { res.status(e.status).json({ error: e.message }); return; }
  res.status(500).json({ error: 'No se pudo generar el dossier.' });
}

dossierRouter.post('/generate', analystPlus, async (req: Request, res: Response) => {
  try {
    const { type, value, range, force } = (req.body ?? {}) as { type?: EntType; value?: string; range?: string; force?: boolean };
    res.json(await generateDossier({ type: type as EntType, value: value ?? '', range }, { force: Boolean(force) }));
  } catch (e) { handle(e, res); }
});

dossierRouter.post('/incident/:id', analystPlus, async (req: Request, res: Response) => {
  try {
    res.json(await generateForIncident(req.params.id, { force: Boolean((req.body ?? {}).force) }));
  } catch (e) { handle(e, res); }
});

dossierRouter.get('/recent', async (_req: Request, res: Response) => {
  try { res.json({ items: await listRecentDossiers(20) }); }
  catch { res.status(500).json({ error: 'No se pudieron listar los dossiers.' }); }
});
