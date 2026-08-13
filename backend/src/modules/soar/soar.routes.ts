/**
 * SOAR: gestión de reglas de respuesta automatizada y cola de aprobación.
 * Lectura para admin/analista; crear/editar reglas y aprobar/rechazar acciones
 * (que ejecutan bloqueos/aislamientos) es solo admin.
 */
import { Router, type Request, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import {
  listRules, createRule, updateRule, removeRule,
  listEvents, pendingCount, resolveEvent, runEngine,
} from './soar.service';

export const soarRouter = Router();
soarRouter.use(authenticate);

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en SOAR');
  res.status(500).json({ error: 'Error interno del servidor' });
}

soarRouter.get('/rules', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json({ rules: await listRules() }); } catch (err) { handle(err, res); }
});

soarRouter.post('/rules', requireRole('admin'), async (req: Request, res: Response) => {
  try {
    const rule = await createRule(req.body ?? {}, req.user!.id);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'soar_rule_create', target: rule.name, result: 'ok', detail: { action: rule.action, mode: rule.mode } });
    res.status(201).json(rule);
  } catch (err) { handle(err, res); }
});

soarRouter.put('/rules/:id', requireRole('admin'), async (req: Request, res: Response) => {
  try { res.json(await updateRule(String(req.params.id), req.body ?? {})); } catch (err) { handle(err, res); }
});

soarRouter.delete('/rules/:id', requireRole('admin'), async (req: Request, res: Response) => {
  try {
    await removeRule(String(req.params.id));
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'soar_rule_remove', target: String(req.params.id), result: 'ok' });
    res.json({ ok: true });
  } catch (err) { handle(err, res); }
});

soarRouter.get('/events', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json({ pending: await pendingCount(), events: await listEvents() }); } catch (err) { handle(err, res); }
});

soarRouter.post('/events/:id/:decision', requireRole('admin'), async (req: Request, res: Response) => {
  const decision = req.params.decision === 'approve' ? 'approve' : req.params.decision === 'reject' ? 'reject' : null;
  if (!decision) { res.status(400).json({ error: 'decisión inválida' }); return; }
  try {
    const ev = await resolveEvent(String(req.params.id), decision, req.user!.id);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: `soar_event_${decision}`, target: ev.entity, result: 'ok', detail: { action: ev.action, status: ev.status } });
    res.json(ev);
  } catch (err) { handle(err, res); }
});

// Ejecuta el motor manualmente (para probar/forzar una evaluación).
soarRouter.post('/run', requireRole('admin'), async (_req, res) => {
  try { res.json(await runEngine()); } catch (err) { handle(err, res); }
});

/** Motor SOAR: evalúa las reglas cada 3 minutos. */
export function startSoarScheduler(): void {
  cron.schedule('*/3 * * * *', () => {
    runEngine()
      .then((r) => { if (r.created) logger.info({ r }, 'SOAR: eventos generados'); })
      .catch((err) => logger.warn({ err: err instanceof Error ? err.message : err }, 'SOAR: fallo en el motor'));
  });
}
