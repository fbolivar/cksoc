/**
 * Riesgo de Datos en Nube (M365).
 *   GET  /api/clouddata?days=24h   ráfagas por usuario (borrado/mod/descarga/compartición)
 *   POST /api/clouddata/refresh    chequeo de ráfagas nuevas (admin/analista)
 * Scheduler: cada CLOUDDATA_CRON (def. cada 2h) avisa por Telegram borrado/mod/exfil masivos
 * NUEVOS (gateado por licencia); baseline al arranque.
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { sendTelegram } from '../notifications/telegram.service';
import { getOverview, ensureSchema, findNew, seedBaseline } from './clouddata.service';

export const cloudDataRouter = Router();
cloudDataRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Riesgo de datos en nube');
  res.status(502).json({ error: 'No se pudo consultar el riesgo de datos en nube' });
}

cloudDataRouter.get('/', canView, async (req, res) => {
  try { const days = typeof req.query.days === 'string' ? req.query.days : '24h'; res.json(await getOverview(days)); } catch (e) { fail(e, res); }
});
cloudDataRouter.post('/refresh', canView, async (_req, res) => {
  try { const fresh = await findNew(); res.json({ ok: true, nuevos: fresh.length }); } catch (e) { fail(e, res); }
});

async function alertNew(): Promise<void> {
  if (!env.TELEGRAM_CHAT_ID) return;
  const fresh = await findNew();
  if (!fresh.length) return;
  const L: string[] = ['☁️ CKAgentico · Riesgo de datos en nube (M365) — ráfagas NUEVAS', ''];
  for (const h of fresh.slice(0, 15)) {
    const icon = h.sev === 'critica' ? '🔴' : h.sev === 'alta' ? '🟠' : '🟡';
    L.push(`${icon} ${h.tipoLabel} — ${h.user}: ${h.count} operaciones (umbral ${h.umbral})`);
  }
  L.push('', 'Posible ransomware en la nube o exfiltración. Verifica con el usuario; si no lo reconoce, suspende la cuenta y revisa OneDrive/SharePoint.');
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
}

export function startCloudDataScheduler(): void {
  void ensureSchema().catch((e) => logger.error({ err: e }, 'clouddata: esquema'));
  const spec = process.env.CLOUDDATA_CRON || '35 */2 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron clouddata inválido'); return; }
  cron.schedule(spec, () => { void alertNew().catch((e) => logger.error({ err: e }, 'clouddata: chequeo')); });
  setTimeout(() => { void seedBaseline().catch((e) => logger.error({ err: e }, 'clouddata: seed')); }, 35_000);
  logger.info(`☁ Riesgo de datos en nube activo (${spec})`);
}
