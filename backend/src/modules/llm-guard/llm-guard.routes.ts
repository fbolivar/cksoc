/**
 * Rutas del LLM Guardrail (firewall de prompts del pipeline de IA de HexWatch).
 *   GET /api/llm-guard/stats?days=   -> estadisticas
 *   GET /api/llm-guard/events?limit= -> eventos recientes
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getGuardStats, getGuardEvents } from './llm-guard.service';

export const llmGuardRouter = Router();
llmGuardRouter.use(authenticate);

llmGuardRouter.get('/stats', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const days = Math.min(90, Math.max(1, Number(req.query.days) || 30));
  try { res.json(await getGuardStats(days)); }
  catch { res.status(500).json({ error: 'No se pudieron calcular las estadisticas del guardrail' }); }
});

llmGuardRouter.get('/events', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 50));
  try { res.json({ events: await getGuardEvents(limit) }); }
  catch { res.status(500).json({ error: 'No se pudieron listar los eventos del guardrail' }); }
});
