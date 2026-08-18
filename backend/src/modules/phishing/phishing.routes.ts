/**
 * Factor humano / campañas de phishing.
 *   GET    /api/phishing            -> { campaigns, metrics }
 *   POST   /api/phishing (admin/analista) -> registrar campaña
 *   DELETE /api/phishing/:id (admin/analista)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { listCampaigns, createCampaign, deleteCampaign, getHumanFactor } from './phishing.service';

export const phishingRouter = Router();
phishingRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

phishingRouter.get('/', async (_req: Request, res: Response) => {
  try {
    const [campaigns, metrics] = await Promise.all([listCampaigns(), getHumanFactor()]);
    res.json({ campaigns, metrics });
  } catch {
    res.status(500).json({ error: 'No se pudieron cargar las campañas' });
  }
});

phishingRouter.post('/', canManage, async (req: Request, res: Response) => {
  const { name, runDate, sent, clicked, reported, trainedPct, note } = req.body ?? {};
  if (!name || !runDate || sent == null) { res.status(400).json({ error: 'name, runDate y sent son obligatorios' }); return; }
  try {
    res.status(201).json(await createCampaign({ name, runDate, sent: Number(sent), clicked: Number(clicked) || 0, reported: Number(reported) || 0, trainedPct: Number(trainedPct) || 0, note }, req.user!.id));
  } catch {
    res.status(500).json({ error: 'No se pudo registrar la campaña' });
  }
});

phishingRouter.delete('/:id', canManage, async (req: Request, res: Response) => {
  try {
    await deleteCampaign(req.params.id);
    res.json({ ok: true });
  } catch {
    res.status(500).json({ error: 'No se pudo borrar la campaña' });
  }
});
