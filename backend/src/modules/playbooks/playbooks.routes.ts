/**
 * Rutas SOAR / Playbooks. Lectura: admin|analista. Cambios: solo admin
 * (habilitar/activar una respuesta automatica es una accion sensible).
 *   GET    /api/playbooks
 *   POST   /api/playbooks                 (admin)
 *   GET    /api/playbooks/runs            historial global
 *   GET    /api/playbooks/:id
 *   PUT    /api/playbooks/:id             (admin)
 *   DELETE /api/playbooks/:id             (admin)
 *   POST   /api/playbooks/:id/test        (admin) simula contra una alerta de ejemplo
 */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import {
  listPlaybooks, getPlaybook, createPlaybook, updatePlaybook, deletePlaybook, listRuns,
  evaluatePlaybook, type AlertContext,
} from './playbooks.service';

export const playbooksRouter = Router();
playbooksRouter.use(authenticate);
const admin = requireRole('admin');

const conditions = z.object({
  minLevel: z.number().int().min(0).max(16).optional(),
  ruleIds: z.array(z.string()).optional(),
  mitre: z.array(z.string()).optional(),
  agents: z.array(z.string()).optional(),
  groups: z.array(z.string()).optional(),
});
const actions = z.array(z.object({ type: z.enum(['block_ip', 'create_incident', 'notify']) })).min(1);
const createSchema = z.object({
  name: z.string().min(3).max(120),
  description: z.string().max(500).optional(),
  mode: z.enum(['simulacion', 'activo']).optional(),
  enabled: z.boolean().optional(),
  conditions,
  actions,
  cooldownMin: z.number().int().min(0).max(1440).optional(),
});
const updateSchema = createSchema.partial();

playbooksRouter.get('/', async (_req, res: Response) => {
  try { res.json({ playbooks: await listPlaybooks() }); }
  catch { res.status(500).json({ error: 'No se pudieron listar los playbooks' }); }
});

playbooksRouter.get('/runs', async (req: Request, res: Response) => {
  try { res.json({ runs: await listRuns(undefined, 100) }); }
  catch { res.status(500).json({ error: 'No se pudo cargar el historial' }); }
});

playbooksRouter.post('/', admin, async (req: Request, res: Response) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors }); return; }
  try {
    const pb = await createPlaybook({ ...parsed.data, createdBy: req.user!.id });
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'playbook_create', target: pb.name, result: 'ok', detail: { mode: pb.mode, enabled: pb.enabled } });
    res.status(201).json(pb);
  } catch { res.status(500).json({ error: 'No se pudo crear el playbook' }); }
});

playbooksRouter.get('/:id', async (req: Request, res: Response) => {
  const pb = await getPlaybook(req.params.id);
  if (!pb) { res.status(404).json({ error: 'Playbook no encontrado' }); return; }
  res.json(pb);
});

playbooksRouter.put('/:id', admin, async (req: Request, res: Response) => {
  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos' }); return; }
  try {
    const pb = await updatePlaybook(req.params.id, parsed.data);
    if (!pb) { res.status(404).json({ error: 'Playbook no encontrado' }); return; }
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'playbook_update', target: pb.name, result: 'ok', detail: parsed.data });
    res.json(pb);
  } catch { res.status(500).json({ error: 'No se pudo actualizar el playbook' }); }
});

playbooksRouter.delete('/:id', admin, async (req: Request, res: Response) => {
  const ok = await deletePlaybook(req.params.id);
  if (!ok) { res.status(404).json({ error: 'Playbook no encontrado' }); return; }
  void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'playbook_delete', target: req.params.id, result: 'ok' });
  res.json({ ok: true });
});

/** Prueba: ejecuta el playbook contra una alerta de ejemplo (respeta su modo). */
playbooksRouter.post('/:id/test', admin, async (req: Request, res: Response) => {
  const pb = await getPlaybook(req.params.id);
  if (!pb) { res.status(404).json({ error: 'Playbook no encontrado' }); return; }
  const b = req.body ?? {};
  const sample: AlertContext = {
    alertId: 'test-' + Date.now(),
    level: Number(b.level ?? pb.conditions.minLevel ?? 12),
    ruleId: String(b.ruleId ?? pb.conditions.ruleIds?.[0] ?? '0000'),
    description: String(b.description ?? 'Alerta de prueba de playbook'),
    agent: String(b.agent ?? pb.conditions.agents?.[0] ?? 'AGENTE-PRUEBA'),
    ip: b.ip ?? '203.0.113.10',
    mitre: b.mitre ?? pb.conditions.mitre ?? [],
    groups: b.groups ?? pb.conditions.groups ?? [],
    timestamp: new Date().toISOString(),
  };
  try {
    const results = await evaluatePlaybook(pb, sample, { ignoreCooldown: true });
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'playbook_test', target: pb.name, result: 'ok' });
    res.json({ ok: true, matched: results !== null, sample, results });
  } catch { res.status(500).json({ error: 'Fallo la prueba' }); }
});
