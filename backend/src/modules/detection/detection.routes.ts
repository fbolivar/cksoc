/**
 * Gestión de detecciones: ver reglas ruidosas y administrar supresiones de FP.
 * Lectura para admin/analista; la escritura (crea/borra reglas + reinicia el
 * manager) queda restringida a admin.
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import {
  getNoisyRules, getCustomRules, listSuppressions, addSuppression, removeSuppression, ALLOWED_FIELDS,
} from './detection.service';

export const detectionRouter = Router();
detectionRouter.use(authenticate);

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  // eslint-disable-next-line no-console
  console.error('Error en detección:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
}

detectionRouter.get('/noisy', requireRole('admin', 'analista'), async (req, res) => {
  const range = typeof req.query.range === 'string' ? req.query.range : '24h';
  try { res.json({ range, rules: await getNoisyRules(range) }); }
  catch (err) { handle(err, res); }
});

detectionRouter.get('/rules', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json({ rules: await getCustomRules() }); }
  catch (err) { handle(err, res); }
});

detectionRouter.get('/suppressions', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json({ fields: ALLOWED_FIELDS, suppressions: await listSuppressions() }); }
  catch (err) { handle(err, res); }
});

detectionRouter.post('/suppressions', requireRole('admin'), async (req: Request, res: Response) => {
  const { targetRuleId, field, value, comment } = req.body ?? {};
  try {
    const s = await addSuppression({
      targetRuleId: String(targetRuleId ?? ''), field: String(field ?? ''),
      value: String(value ?? ''), comment: String(comment ?? ''),
    });
    void auditFromReq(req, {
      actorId: req.user!.id, actorEmail: req.user!.email,
      action: 'detection_suppress_add', target: `regla ${s.targetRuleId}`, result: 'ok',
      detail: { id: s.id, field: s.field, value: s.value },
    });
    res.status(201).json(s);
  } catch (err) { handle(err, res); }
});

detectionRouter.delete('/suppressions/:id', requireRole('admin'), async (req: Request, res: Response) => {
  const id = Number(req.params.id);
  try {
    await removeSuppression(id);
    void auditFromReq(req, {
      actorId: req.user!.id, actorEmail: req.user!.email,
      action: 'detection_suppress_remove', target: String(id), result: 'ok',
    });
    res.json({ ok: true });
  } catch (err) { handle(err, res); }
});
