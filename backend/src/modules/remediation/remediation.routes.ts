/**
 * Panel de Remediación (MVP winget). Todas las rutas exigen rol admin.
 *  GET  /api/remediation/hosts        -> hosts Windows candidatos + lista piloto
 *  POST /api/remediation/scan {host}  -> dry-run (sólo lectura): lista de updates
 *  POST /api/remediation/apply {host, packageId, confirm} -> instala/actualiza (sólo piloto)
 *  GET  /api/remediation/job/:id      -> estado/resultado del job
 *  GET  /api/remediation/jobs         -> historial reciente
 * Cada scan/apply queda auditado.
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import {
  listRemediationHosts, startScan, startApply, startAutoEnable, getJob, recentJobs, pilotHosts, allowAllHosts,
} from './remediation.service';

export const remediationRouter = Router();
remediationRouter.use(authenticate);

remediationRouter.get('/hosts', requireRole('admin'), async (_req, res) => {
  try {
    const hosts = await listRemediationHosts();
    res.json({ hosts, pilotHosts: pilotHosts(), allowAll: allowAllHosts() });
  } catch (e) {
    res.status(502).json({ error: (e as Error).message });
  }
});

// Escaneo dry-run (sólo lectura): NO instala nada.
remediationRouter.post('/scan', requireRole('admin'), async (req: Request, res: Response) => {
  const host = String(req.body?.host || '').trim();
  try {
    const job = await startScan(host, req.user!.email);
    void auditFromReq(req, {
      actorId: req.user!.id, actorEmail: req.user!.email,
      action: 'remediation_scan', target: host, result: 'ok',
      detail: { job_id: job.id, client_id: job.client_id, flow_id: job.flow_id },
    });
    res.status(202).json({ job });
  } catch (e) {
    res.status(400).json({ error: (e as Error).message });
  }
});

// Aplicar actualización (instala). Sólo hosts piloto; requiere confirm explícito.
remediationRouter.post('/apply', requireRole('admin'), async (req: Request, res: Response) => {
  const host = String(req.body?.host || '').trim();
  const packageId = String(req.body?.packageId || '').trim();
  const confirm = req.body?.confirm === true;
  if (!confirm) { res.status(400).json({ error: 'Falta confirmación explícita (confirm=true).' }); return; }
  try {
    const job = await startApply(host, packageId, req.user!.email);
    void auditFromReq(req, {
      actorId: req.user!.id, actorEmail: req.user!.email,
      action: 'remediation_apply', target: `${host}:${packageId}`, result: 'ok',
      detail: { job_id: job.id, client_id: job.client_id, flow_id: job.flow_id, package: packageId },
    });
    res.status(202).json({ job });
  } catch (e) {
    const msg = (e as Error).message;
    const code = /piloto/.test(msg) ? 403 : 400;
    if (code === 403) {
      void auditFromReq(req, {
        actorId: req.user!.id, actorEmail: req.user!.email,
        action: 'remediation_apply_blocked', target: `${host}:${packageId}`, result: 'fail', detail: { reason: msg },
      });
    }
    res.status(code).json({ error: msg });
  }
});

// Activar automatización nativa de parches de seguridad (unattended-upgrades) en Linux.
// Sólo hosts piloto; requiere confirm explícito. Instala/configura en el endpoint.
remediationRouter.post('/autoenable', requireRole('admin'), async (req: Request, res: Response) => {
  const host = String(req.body?.host || '').trim();
  const confirm = req.body?.confirm === true;
  if (!confirm) { res.status(400).json({ error: 'Falta confirmación explícita (confirm=true).' }); return; }
  try {
    const job = await startAutoEnable(host, req.user!.email);
    void auditFromReq(req, {
      actorId: req.user!.id, actorEmail: req.user!.email,
      action: 'remediation_autoenable', target: host, result: 'ok',
      detail: { job_id: job.id, client_id: job.client_id, flow_id: job.flow_id },
    });
    res.status(202).json({ job });
  } catch (e) {
    const msg = (e as Error).message;
    res.status(/piloto|Linux/.test(msg) ? 403 : 400).json({ error: msg });
  }
});

remediationRouter.get('/job/:id', requireRole('admin'), async (req: Request, res: Response) => {
  const id = String(req.params.id || '');
  if (!/^[0-9a-f-]{36}$/i.test(id)) { res.status(400).json({ error: 'id inválido' }); return; }
  const job = await getJob(id);
  if (!job) { res.status(404).json({ error: 'job no encontrado' }); return; }
  res.json({ job });
});

remediationRouter.get('/jobs', requireRole('admin'), async (_req, res) => {
  res.json({ jobs: await recentJobs(20) });
});
