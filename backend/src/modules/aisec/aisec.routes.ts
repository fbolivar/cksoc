/**
 * AI Security — Inventario de IA + Monitoreo de M365 Copilot. Admin/analista.
 *   GET /api/aisec/inventory?range=24h|7d|30d
 *   GET /api/aisec/copilot?range=24h|7d|30d
 * Scheduler diario: avisa por Telegram si hay intentos de jailbreak (prompt
 * injection) en Copilot. La sanción (aprobado/shadow) se gestiona desde el
 * módulo Shadow-AI (comparte la tabla shadow_ai_policy).
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { sendTelegram } from '../notifications/telegram.service';
import { getInventory, getCopilot, getOverview, getExfiltration, getRisk, getPosture } from './aisec.service';

export const aisecRouter = Router();
aisecRouter.use(authenticate);
const canManage = requireRole('admin', 'analista');

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en AI-Security');
  res.status(500).json({ error: 'Error interno del servidor' });
}

aisecRouter.get('/inventory', canManage, async (req, res) => {
  try { res.json(await getInventory(typeof req.query.range === 'string' ? req.query.range : '7d')); } catch (e) { handle(e, res); }
});
aisecRouter.get('/copilot', canManage, async (req, res) => {
  try { res.json(await getCopilot(typeof req.query.range === 'string' ? req.query.range : '7d')); } catch (e) { handle(e, res); }
});
aisecRouter.get('/overview', canManage, async (req, res) => { try { res.json(await getOverview(typeof req.query.range === 'string' ? req.query.range : '7d')); } catch (e) { handle(e, res); } });
aisecRouter.get('/exfiltration', canManage, async (req, res) => { try { res.json(await getExfiltration(typeof req.query.range === 'string' ? req.query.range : '7d')); } catch (e) { handle(e, res); } });
aisecRouter.get('/risk', canManage, async (req, res) => { try { res.json(await getRisk(typeof req.query.range === 'string' ? req.query.range : '7d')); } catch (e) { handle(e, res); } });
aisecRouter.get('/posture', canManage, async (req, res) => { try { res.json(await getPosture(typeof req.query.range === 'string' ? req.query.range : '7d')); } catch (e) { handle(e, res); } });

/** Scheduler: revisión diaria de intentos de jailbreak en Copilot. */
export function startAiSecScheduler(): void {
  if (String(process.env.AISEC_ENABLED ?? 'true').toLowerCase() === 'false') { logger.info('🧠 AI-Security desactivado (AISEC_ENABLED=false)'); return; }
  const spec = process.env.AISEC_SCAN_CRON || '35 5 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de AI-Security inválido'); return; }
  cron.schedule(spec, async () => {
    try {
      const c = await getCopilot('24h');
      logger.info({ interactions: c.interactions, users: c.users, jailbreak: c.jailbreakAttempts }, '🧠 Revisión AI-Security (Copilot) completada');
      if (c.jailbreakAttempts > 0 && env.TELEGRAM_CHAT_ID) {
        const L = [
          '🧠 Agentico · Seguridad de IA — intento(s) de manipulación en Copilot',
          '',
          `Detecté ${c.jailbreakAttempts} interacción(es) de M365 Copilot marcadas como posible jailbreak / prompt-injection en 24 h.`,
          '',
        ];
        for (const j of c.jailbreakList.slice(0, 8)) L.push(`• ${j.user} · ${j.app} · ${j.time.slice(0, 16).replace('T', ' ')}`);
        L.push('', 'Recomiendo revisar a esos usuarios (uso indebido o cuenta comprometida intentando evadir las barreras del asistente).');
        await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
      }
    } catch (e) { logger.error({ err: e }, 'Error en revisión AI-Security programada'); }
  });
  logger.info(`🧠 AI-Security activo (${spec})`);
}
