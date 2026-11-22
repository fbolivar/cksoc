/**
 * Monitor de Consentimientos OAuth (M365).
 *   GET  /api/oauth-apps           inventario de apps consentidas + riesgo
 *   POST /api/oauth-apps/refresh   fuerza chequeo de apps riesgosas nuevas (admin/analista)
 * Scheduler: cada OAUTH_APPS_CRON (def. cada 6h) avisa por Telegram apps riesgosas NUEVAS
 * (gateado por licencia); siembra baseline al arranque para no spamear lo existente.
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { sendTelegram } from '../notifications/telegram.service';
import { getOverview, ensureSchema, findNewRisky, seedBaseline, isGraphConfigured } from './oauthapps.service';

export const oauthAppsRouter = Router();
oauthAppsRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en OAuth apps');
  res.status(502).json({ error: 'No se pudo consultar los consentimientos OAuth (Graph)' });
}

oauthAppsRouter.get('/', canView, async (_req, res) => {
  try { res.json(await getOverview()); } catch (e) { fail(e, res); }
});
oauthAppsRouter.post('/refresh', canView, async (_req, res) => {
  try { const fresh = await findNewRisky(); res.json({ ok: true, nuevas: fresh.length }); } catch (e) { fail(e, res); }
});

async function alertNew(): Promise<void> {
  if (!env.TELEGRAM_CHAT_ID) return;
  const fresh = await findNewRisky();
  if (!fresh.length) return;
  const L: string[] = ['🔑 CKAgentico · Consentimientos OAuth (M365) — apps de terceros riesgosas NUEVAS', ''];
  for (const a of fresh.slice(0, 15)) {
    const icon = a.risk === 'critica' ? '🔴' : '🟠';
    L.push(`${icon} ${a.name}${a.verified ? '' : ' (editor no verificado)'} — ${a.consent === 'organizacion' ? 'toda la org' : 'por usuario'}`);
    if (a.appRoles.length) L.push(`   app-only: ${a.appRoles.slice(0, 4).join(', ')}`);
    else if (a.scopes.length) L.push(`   permisos: ${a.scopes.slice(0, 5).join(', ')}`);
  }
  L.push('', 'Revisa en M365 → Enterprise applications. Si no la reconoces, revoca el consentimiento.');
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
}

export function startOAuthAppsScheduler(): void {
  if (!isGraphConfigured()) { logger.info('🔑 OAuth apps: Graph no configurado, monitor inactivo'); return; }
  void ensureSchema().catch((e) => logger.error({ err: e }, 'OAuth apps: esquema'));
  const spec = process.env.OAUTH_APPS_CRON || '40 */6 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron OAuth apps inválido'); return; }
  cron.schedule(spec, () => { void alertNew().catch((e) => logger.error({ err: e }, 'OAuth apps: chequeo')); });
  setTimeout(() => { void seedBaseline().catch((e) => logger.error({ err: e }, 'OAuth apps: seed')); }, 25_000);
  logger.info(`🔑 Monitor de consentimientos OAuth activo (${spec})`);
}
