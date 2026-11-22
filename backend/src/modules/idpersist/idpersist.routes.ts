/**
 * Persistencia de Identidad (M365).
 *   GET  /api/idpersist?days=30   detecciones de persistencia (MFA/delegación/CA/token)
 *   POST /api/idpersist/refresh   chequeo de nuevas (admin/analista)
 * Scheduler: cada IDP_CRON (def. cada 3h) avisa por Telegram cambios de MFA o delegaciones
 * de buzón NUEVOS (gateado por licencia); baseline al arranque para no spamear histórico.
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { sendTelegram } from '../notifications/telegram.service';
import { getOverview, ensureSchema, findNew, seedBaseline } from './idpersist.service';

export const idpersistRouter = Router();
idpersistRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Persistencia de identidad');
  res.status(502).json({ error: 'No se pudo consultar la persistencia de identidad' });
}

idpersistRouter.get('/', canView, async (req, res) => {
  try { const days = typeof req.query.days === 'string' ? req.query.days : '30d'; res.json(await getOverview(days)); } catch (e) { fail(e, res); }
});
idpersistRouter.post('/refresh', canView, async (_req, res) => {
  try { const fresh = await findNew(); res.json({ ok: true, nuevos: fresh.length }); } catch (e) { fail(e, res); }
});

async function alertNew(): Promise<void> {
  if (!env.TELEGRAM_CHAT_ID) return;
  const fresh = await findNew();
  if (!fresh.length) return;
  const L: string[] = ['🧬 CKAgentico · Persistencia de identidad (M365) — eventos NUEVOS', ''];
  for (const h of fresh.slice(0, 15)) L.push(`🔴 ${h.tipoLabel} — ${h.user}${h.ip ? ` · IP ${h.ip}` : ''}\n   ${h.detalle}`);
  L.push('', 'Posible persistencia tras robo de cuenta. Verifica con el usuario; si no lo reconoce, revoca sesiones y revisa MFA/delegaciones.');
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
}

export function startIdpersistScheduler(): void {
  void ensureSchema().catch((e) => logger.error({ err: e }, 'idp: esquema'));
  const spec = process.env.IDP_CRON || '50 */3 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron idp inválido'); return; }
  cron.schedule(spec, () => { void alertNew().catch((e) => logger.error({ err: e }, 'idp: chequeo')); });
  setTimeout(() => { void seedBaseline().catch((e) => logger.error({ err: e }, 'idp: seed')); }, 30_000);
  logger.info(`🧬 Persistencia de identidad activa (${spec})`);
}
