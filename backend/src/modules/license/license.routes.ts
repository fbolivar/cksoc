/**
 * Rutas de licenciamiento (exentas del gate).
 *   GET  /api/license/status    estado de la licencia (autenticado)
 *   POST /api/license/activate  cargar un código de activación (ADMIN)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { getLicenseStatus, activateLicense } from './license.service';

export const licenseRouter = Router();
licenseRouter.use(authenticate);

licenseRouter.get('/status', async (_req: Request, res: Response) => {
  res.json(await getLicenseStatus());
});

licenseRouter.post('/activate', requireRole('admin'), async (req: Request, res: Response) => {
  const code = String(req.body?.code ?? '').trim();
  if (!code) { res.status(400).json({ error: 'Código requerido' }); return; }
  const st = await activateLicense(code, req.user!.id);
  void auditFromReq(req, {
    actorId: req.user!.id, actorEmail: req.user!.email,
    action: 'license_activate', target: st.customer ?? 'licencia',
    result: st.state === 'active' ? 'ok' : 'fail', detail: { state: st.state, expiresAt: st.expiresAt },
  });
  res.status(st.state === 'active' ? 200 : 400).json(st);
});
