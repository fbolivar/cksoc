/**
 * Observabilidad — Tendencia de recursos de la infraestructura del SOC.
 *   GET /api/obs/inventory          (nodo + VMs: estado y % actuales)
 *   GET /api/obs/node?timeframe=    (serie RRD del hypervisor)
 *   GET /api/obs/vm/:vmid?timeframe= (serie RRD de una VM)
 * timeframe ∈ hour|day|week|month|year (def. day). Solo lectura (token PVEAuditor),
 * tolerante a que Proxmox no esté disponible (devuelve ok:false, no rompe el panel).
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { getInventory, getNodeTrend, getVmTrend, normTf } from './obs.service';

export const obsRouter = Router();
obsRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Observabilidad');
  res.status(500).json({ error: 'Error interno del servidor' });
}

obsRouter.get('/inventory', canView, async (_req, res) => {
  try { res.json(await getInventory()); } catch (e) { fail(e, res); }
});
obsRouter.get('/node', canView, async (req, res) => {
  try { res.json(await getNodeTrend(normTf(req.query.timeframe as string | undefined))); } catch (e) { fail(e, res); }
});
obsRouter.get('/vm/:vmid', canView, async (req, res) => {
  try {
    const vmid = Number(req.params.vmid);
    if (!Number.isFinite(vmid)) { res.status(400).json({ error: 'vmid inválido' }); return; }
    res.json(await getVmTrend(vmid, normTf(req.query.timeframe as string | undefined)));
  } catch (e) { fail(e, res); }
});
