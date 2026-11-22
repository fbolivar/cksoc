/**
 * Claw-back post-entrega (M365).
 *   POST /api/clawback/preview   { sender?, subject?, internetMessageId?, days? }  (admin/analista, solo lectura)
 *   POST /api/clawback/execute   { ...criterios, confirm:'CONFIRMAR' }             (admin, destructivo/reversible)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { preview, execute, type Criteria } from './clawback.service';

export const clawbackRouter = Router();
clawbackRouter.use(authenticate);

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en claw-back');
  res.status(502).json({ error: 'No se pudo procesar el claw-back' });
}
function criteria(b: Record<string, unknown>): Criteria {
  return {
    sender: typeof b.sender === 'string' ? b.sender : undefined,
    subject: typeof b.subject === 'string' ? b.subject : undefined,
    internetMessageId: typeof b.internetMessageId === 'string' ? b.internetMessageId : undefined,
    days: b.days != null ? Number(b.days) : undefined,
  };
}

clawbackRouter.post('/preview', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try { res.json(await preview(criteria(req.body ?? {}))); } catch (e) { fail(e, res); }
});

clawbackRouter.post('/execute', requireRole('admin'), async (req: Request, res: Response) => {
  try {
    if (req.body?.confirm !== 'CONFIRMAR') { res.status(400).json({ error: 'Confirmación requerida (confirm: "CONFIRMAR")' }); return; }
    const actor = req.user?.email ?? 'desconocido';
    res.json(await execute(criteria(req.body ?? {}), actor));
  } catch (e) { fail(e, res); }
});
