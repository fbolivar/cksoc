/**
 * Rutas de Gestion de Incidentes.
 *   GET    /api/incidents              lista (filtros: status, severity, assignee, q)
 *   GET    /api/incidents/meta/users   usuarios asignables (admin/analista)
 *   POST   /api/incidents              crear            (admin/analista)
 *   GET    /api/incidents/:id          detalle + timeline
 *   PATCH  /api/incidents/:id          estado/severidad/asignacion (admin/analista)
 *   POST   /api/incidents/:id/notes    agregar comentario (admin/analista)
 */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import {
  listIncidents, getIncident, createIncident, updateIncident, addComment, assignableUsers, escalateIncident,
} from './incidents.service';
import { metrics, getPolicy, updatePolicy, slaBreachedIncidents } from './sla.service';
import { auditFromReq } from '../audit/audit.service';

export const incidentsRouter = Router();
incidentsRouter.use(authenticate);
const manage = requireRole('admin', 'analista');

// Recomendaciones: incidentes abiertos con SLA vencido (para escalar). Antes de /:id.
incidentsRouter.get('/recommendations', async (_req: Request, res: Response) => {
  try { res.json({ items: await slaBreachedIncidents(), generatedAt: new Date().toISOString() }); }
  catch { res.status(500).json({ error: 'No se pudieron generar las recomendaciones de SLA' }); }
});

incidentsRouter.get('/metrics', async (req: Request, res: Response) => {
  try {
    const days = req.query.days ? Number(req.query.days) : 90;
    res.json(await metrics(days));
  } catch {
    res.status(500).json({ error: 'No se pudieron calcular las métricas' });
  }
});

incidentsRouter.get('/sla', async (_req: Request, res: Response) => {
  try { res.json({ policy: await getPolicy() }); } catch { res.status(500).json({ error: 'No se pudo leer la política SLA' }); }
});

incidentsRouter.put('/sla', requireRole('admin'), async (req: Request, res: Response) => {
  try { res.json({ policy: await updatePolicy(req.body?.policy ?? []) }); } catch { res.status(500).json({ error: 'No se pudo actualizar la política SLA' }); }
});

const sevEnum = z.enum(['baja', 'media', 'alta', 'critica']);
const statusEnum = z.enum(['abierto', 'en_curso', 'resuelto', 'cerrado']);
const str = (req: Request, k: string) => (typeof req.query[k] === 'string' && req.query[k] ? String(req.query[k]) : undefined);

incidentsRouter.get('/', async (req: Request, res: Response) => {
  try {
    res.json({ incidents: await listIncidents({ status: str(req, 'status'), severity: str(req, 'severity'), assignee: str(req, 'assignee'), q: str(req, 'q') }) });
  } catch {
    res.status(500).json({ error: 'No se pudo listar incidentes' });
  }
});

incidentsRouter.get('/meta/users', manage, async (_req: Request, res: Response) => {
  try {
    res.json({ users: await assignableUsers() });
  } catch {
    res.status(500).json({ error: 'No se pudo cargar usuarios' });
  }
});

const createSchema = z.object({
  title: z.string().min(3).max(200),
  description: z.string().max(5000).optional(),
  severity: sevEnum.default('media'),
  source: z.record(z.string(), z.unknown()).optional(),
});

incidentsRouter.post('/', manage, async (req: Request, res: Response) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos inválidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    res.status(201).json(await createIncident(parsed.data, req.user!.id));
  } catch {
    res.status(500).json({ error: 'No se pudo crear el incidente' });
  }
});

incidentsRouter.get('/:id', async (req: Request, res: Response) => {
  try {
    const inc = await getIncident(req.params.id);
    if (!inc) { res.status(404).json({ error: 'Incidente no encontrado' }); return; }
    res.json(inc);
  } catch {
    res.status(500).json({ error: 'No se pudo cargar el incidente' });
  }
});

const patchSchema = z.object({
  status: statusEnum.optional(),
  severity: sevEnum.optional(),
  assigneeId: z.string().uuid().nullable().optional(),
});

incidentsRouter.patch('/:id', manage, async (req: Request, res: Response) => {
  const parsed = patchSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos inválidos' });
    return;
  }
  try {
    const inc = await updateIncident(req.params.id, parsed.data, req.user!.id);
    if (!inc) { res.status(404).json({ error: 'Incidente no encontrado' }); return; }
    res.json(inc);
  } catch {
    res.status(500).json({ error: 'No se pudo actualizar el incidente' });
  }
});

incidentsRouter.post('/:id/escalate', manage, async (req: Request, res: Response) => {
  try {
    const r = await escalateIncident(req.params.id, req.user!.id);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'incident_escalate', target: req.params.id, result: 'ok', detail: { delivered: r.delivered, onCall: r.onCall } });
    res.json(r);
  } catch (e) {
    const status = (e as { status?: number }).status ?? 500;
    res.status(status).json({ error: (e as { message?: string }).message ?? 'No se pudo escalar el incidente' });
  }
});

incidentsRouter.post('/:id/notes', manage, async (req: Request, res: Response) => {
  const parsed = z.object({ note: z.string().min(1).max(5000) }).safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Nota inválida' });
    return;
  }
  try {
    const inc = await addComment(req.params.id, parsed.data.note, req.user!.id);
    if (!inc) { res.status(404).json({ error: 'Incidente no encontrado' }); return; }
    res.json(inc);
  } catch {
    res.status(500).json({ error: 'No se pudo agregar la nota' });
  }
});
