/**
 * Dashboard Office 365.
 *   GET /api/office365?range=24h|7d|30d
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getO365Overview, getExposedUnderAttack } from './o365.service';
import { listM365Identities, getIdentityRecommendations, disableM365User, deleteM365User } from '../identity/identity.service';
import { auditFromReq } from '../audit/audit.service';

export const office365Router = Router();
office365Router.use(authenticate);

function fail(err: unknown, res: Response, fallback: string): void {
  const status = (err as { status?: number }).status ?? 502;
  res.status(status).json({ error: (err as { message?: string }).message ?? fallback });
}

office365Router.get('/', async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '24h';
    res.json(await getO365Overview(range));
  } catch {
    res.status(500).json({ error: 'No se pudo construir el dashboard de Office 365' });
  }
});

// Correlación credenciales-expuestas ↔ ataques (logins fallidos O365). Solo lectura.
office365Router.get('/exposed-under-attack', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const range = typeof req.query.range === 'string' ? req.query.range : '7d';
    res.json(await getExposedUnderAttack(range));
  } catch (e) {
    fail(e, res, 'No se pudo correlacionar credenciales expuestas con ataques');
  }
});

// Directorio de identidades del tenant vía Microsoft Graph (solo lectura).
office365Router.get('/identities', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try {
    res.json(await listM365Identities());
  } catch (e) {
    fail(e, res, 'No se pudo consultar el directorio M365');
  }
});

// Recomendaciones de higiene de identidad (invitados externos) — solo lectura.
office365Router.get('/recommendations', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try {
    res.json(await getIdentityRecommendations());
  } catch (e) {
    fail(e, res, 'No se pudieron generar las recomendaciones de identidad');
  }
});

// Acción: deshabilitar una cuenta M365 (reversible). admin/analista.
office365Router.post('/identities/disable', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const upn = String(req.body?.upn ?? '').trim();
  try {
    const r = await disableM365User(upn);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'm365_disable_user', target: upn, result: 'ok' });
    res.json(r);
  } catch (e) {
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'm365_disable_user', target: upn, result: 'fail', detail: { error: (e as { message?: string }).message } });
    fail(e, res, 'No se pudo deshabilitar la cuenta');
  }
});

// Acción: eliminar una cuenta M365 (destructivo). Solo admin.
office365Router.post('/identities/delete', requireRole('admin'), async (req: Request, res: Response) => {
  const upn = String(req.body?.upn ?? '').trim();
  try {
    const r = await deleteM365User(upn);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'm365_delete_user', target: upn, result: 'ok' });
    res.json(r);
  } catch (e) {
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'm365_delete_user', target: upn, result: 'fail', detail: { error: (e as { message?: string }).message } });
    fail(e, res, 'No se pudo eliminar la cuenta');
  }
});
