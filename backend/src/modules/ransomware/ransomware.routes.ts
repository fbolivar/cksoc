/**
 * Inteligencia de Ransomware.
 *   GET  /api/ransomware?days=30   (grupos activos + víctimas recientes + relevantes)
 *   POST /api/ransomware/refresh   (fuerza chequeo de nuevas relevantes; admin/analista)
 * Scheduler: cada RANSOMWARE_CRON (def. cada 6h) busca nuevas víctimas relevantes y
 * avisa por Telegram (gateado por licencia). Siembra baseline al arranque sin spamear.
 */
import { Router, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { env } from '../../config/env';
import { sendTelegram } from '../notifications/telegram.service';
import { getOverview, ensureSchema, findNewRelevant, seedBaseline, type RwVictim } from './ransomware.service';

export const ransomwareRouter = Router();
ransomwareRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

function fail(err: unknown, res: Response): void {
  logger.error({ err }, 'Error en Ransomware Intel');
  res.status(502).json({ error: 'No se pudo consultar la fuente de inteligencia de ransomware' });
}

ransomwareRouter.get('/', canView, async (req, res) => {
  try {
    const days = req.query.days != null ? Number(req.query.days) : 30;
    res.json(await getOverview(Number.isFinite(days) ? days : 30));
  } catch (e) { fail(e, res); }
});

ransomwareRouter.post('/refresh', canView, async (_req, res) => {
  try { const fresh = await findNewRelevant(); res.json({ ok: true, nuevos: fresh.length }); }
  catch (e) { fail(e, res); }
});

function line(v: RwVictim): string {
  const icon = v.relevance === 'directo' ? '🔴' : v.relevance === 'pais' ? '🟡' : '🟠';
  const extra = v.relevance === 'directo' ? ' — ¡COINCIDENCIA DIRECTA!' : '';
  return `${icon} [${v.group}] ${v.victim}${v.country ? ` (${v.country})` : ''}${v.sector ? ` · ${v.sector}` : ''}${extra}`;
}

async function alertNew(): Promise<void> {
  if (!env.TELEGRAM_CHAT_ID) return;
  const fresh = await findNewRelevant();
  if (!fresh.length) return;
  const L: string[] = ['🩸 CKAgentico · Inteligencia de Ransomware — nuevas víctimas relevantes', ''];
  for (const v of fresh.slice(0, 20)) L.push(line(v));
  if (fresh.length > 20) L.push(`… y ${fresh.length - 20} más`);
  L.push('', 'Fuente: ransomware.live (sitios de extorsión). Relevancia = marca/dominio del cliente, país o sector.');
  await sendTelegram([env.TELEGRAM_CHAT_ID], L.join('\n'), { plain: true }).catch(() => undefined);
}

export function startRansomwareScheduler(): void {
  void ensureSchema().catch((e) => logger.error({ err: e }, 'Ransomware: no se pudo preparar el esquema'));
  const spec = process.env.RANSOMWARE_CRON || '15 */6 * * *';
  if (!cron.validate(spec)) { logger.error({ cron: spec }, 'Cron de Ransomware inválido'); return; }
  cron.schedule(spec, () => { void alertNew().catch((e) => logger.error({ err: e }, 'Ransomware: error en chequeo programado')); });
  // Siembra baseline al arranque (sin alertar histórico), luego el cron solo avisa lo nuevo.
  setTimeout(() => { void seedBaseline().catch((e) => logger.error({ err: e }, 'Ransomware: seed baseline')); }, 20_000);
  logger.info(`🩸 Inteligencia de Ransomware activa (${spec})`);
}
