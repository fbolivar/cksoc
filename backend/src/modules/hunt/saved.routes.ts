/**
 * Rutas de cacerías guardadas (admin | analista).
 *   GET/POST         /api/hunt/saved
 *   PUT/DELETE       /api/hunt/saved/:id
 *   POST             /api/hunt/saved/:id/run
 */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import {
  listSavedHunts, createSavedHunt, updateSavedHunt, deleteSavedHunt, runSavedHunt,
} from './saved.service';

export const savedHuntRouter = Router();
savedHuntRouter.use(authenticate, requireRole('admin', 'analista'));

const querySchema = z.object({
  range: z.string().optional(),
  q: z.string().optional(),
  agent: z.string().optional(),
  ruleId: z.string().optional(),
  minLevel: z.number().optional(),
  srcip: z.string().optional(),
  mitre: z.string().optional(),
});
const createSchema = z.object({
  name: z.string().min(2).max(120),
  query: querySchema,
  alertEnabled: z.boolean().optional(),
  threshold: z.number().int().min(1).max(100000).optional(),
  intervalMin: z.number().int().min(5).max(1440).optional(),
});

savedHuntRouter.get('/', async (_req, res: Response) => {
  try { res.json({ hunts: await listSavedHunts() }); }
  catch { res.status(500).json({ error: 'No se pudieron listar las cacerías' }); }
});

savedHuntRouter.post('/', async (req: Request, res: Response) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos' }); return; }
  try { res.status(201).json(await createSavedHunt({ ...parsed.data, createdBy: req.user!.id })); }
  catch { res.status(500).json({ error: 'No se pudo guardar la cacería' }); }
});

savedHuntRouter.put('/:id', async (req: Request, res: Response) => {
  const parsed = createSchema.partial().safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos' }); return; }
  const h = await updateSavedHunt(req.params.id, parsed.data);
  if (!h) { res.status(404).json({ error: 'Cacería no encontrada' }); return; }
  res.json(h);
});

savedHuntRouter.delete('/:id', async (req: Request, res: Response) => {
  const ok = await deleteSavedHunt(req.params.id);
  if (!ok) { res.status(404).json({ error: 'Cacería no encontrada' }); return; }
  res.json({ ok: true });
});

savedHuntRouter.post('/:id/run', async (req: Request, res: Response) => {
  const r = await runSavedHunt(req.params.id);
  if (!r) { res.status(404).json({ error: 'Cacería no encontrada' }); return; }
  res.json(r);
});
