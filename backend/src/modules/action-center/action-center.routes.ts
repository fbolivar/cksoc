/**
 * Centro de Acción: cola unificada (GET /) y despachador de acciones (POST /execute).
 * El despachador reutiliza las acciones de cada módulo (con su lista blanca/rol/
 * auditoría) para que el operador actúe con un clic sin salir de la cola.
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { getActionQueue, type ActionKind } from './action-center.service';
import { block } from '../response/response.service';
import { disableM365User, deleteM365User } from '../identity/identity.service';
import { escalateIncident } from '../incidents/incidents.service';
import { resolveEvent } from '../soar/soar.service';
import { runHelper } from '../velociraptor/velociraptor.helper';

export const actionCenterRouter = Router();
actionCenterRouter.use(authenticate);

actionCenterRouter.get('/', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try { res.json(await getActionQueue()); }
  catch (e) { res.status(502).json({ error: (e as Error).message ?? 'No se pudo construir la cola de acción' }); }
});

// Acciones destructivas / de red / SOAR: solo admin. El resto: admin+analista.
const ADMIN_ONLY: ActionKind[] = ['block_ip', 'delete_m365', 'soar_approve', 'soar_reject'];

actionCenterRouter.post('/execute', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const kind = String(req.body?.kind ?? '') as ActionKind;
  const params = (req.body?.params ?? {}) as Record<string, string>;
  if (ADMIN_ONLY.includes(kind) && req.user!.role !== 'admin') {
    res.status(403).json({ error: 'Esta acción requiere rol admin' });
    return;
  }
  const user = { id: req.user!.id, email: req.user!.email };
  const target = params.ip ?? params.upn ?? params.host ?? params.id ?? '';
  try {
    let result: unknown;
    switch (kind) {
      case 'block_ip':
        await block({ ip: params.ip, motivo: 'Centro de Acción', user, adminIp: req.ip });
        result = { blocked: params.ip }; break;
      case 'disable_m365': result = await disableM365User(params.upn); break;
      case 'delete_m365': result = await deleteM365User(params.upn); break;
      case 'escalate': result = await escalateIncident(params.id, user.id); break;
      case 'collect': {
        const r = await runHelper(['collect', params.host]);
        if (r?.error) throw new HttpError(502, String(r.error));
        result = r; break;
      }
      case 'soar_approve': result = await resolveEvent(params.id, 'approve', user.id); break;
      case 'soar_reject': result = await resolveEvent(params.id, 'reject', user.id); break;
      default: res.status(400).json({ error: 'Acción desconocida' }); return;
    }
    void auditFromReq(req, { actorId: user.id, actorEmail: user.email, action: `action_center_${kind}`, target, result: 'ok', detail: { kind } });
    res.json({ ok: true, kind, result });
  } catch (e) {
    void auditFromReq(req, { actorId: user.id, actorEmail: user.email, action: `action_center_${kind}`, target, result: 'fail', detail: { kind, error: (e as { message?: string }).message } });
    const status = (e as { status?: number }).status ?? 500;
    res.status(status).json({ error: (e as { message?: string }).message ?? 'No se pudo ejecutar la acción' });
  }
});
