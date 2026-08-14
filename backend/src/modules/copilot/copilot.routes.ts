/**
 * Copiloto IA: chat asistido, explicación de alertas y resumen de incidentes.
 * Sólo admin/analista. Cada invocación queda auditada (envía contexto a la nube).
 */
import { Router, type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import { isConfigured, chat, explain, summarizeIncident, type ChatMessage } from './copilot.service';

export const copilotRouter = Router();
copilotRouter.use(authenticate);

// Límite propio: el copiloto llama a una API de pago; evita abuso/costos.
const copilotLimiter = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas consultas al copiloto. Espera un momento.' },
});

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en el copiloto');
  res.status(500).json({ error: 'Error interno del servidor' });
}

copilotRouter.get('/status', requireRole('admin', 'analista'), (_req, res) => {
  res.json({ enabled: isConfigured() });
});

copilotRouter.post('/chat', requireRole('admin', 'analista'), copilotLimiter, async (req: Request, res: Response) => {
  try {
    const message = String(req.body?.message ?? '');
    const history = (req.body?.history ?? []) as ChatMessage[];
    const out = await chat(history, message);
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'copilot_chat', target: message.slice(0, 80), result: 'ok' });
    res.json(out);
  } catch (err) { handle(err, res); }
});

copilotRouter.post('/explain', requireRole('admin', 'analista'), copilotLimiter, async (req: Request, res: Response) => {
  try {
    const out = await explain(String(req.body?.text ?? ''));
    res.json(out);
  } catch (err) { handle(err, res); }
});

copilotRouter.post('/incident/:id/summary', requireRole('admin', 'analista'), copilotLimiter, async (req: Request, res: Response) => {
  try {
    const out = await summarizeIncident(String(req.params.id));
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'copilot_incident_summary', target: String(req.params.id), result: 'ok' });
    res.json(out);
  } catch (err) { handle(err, res); }
});
