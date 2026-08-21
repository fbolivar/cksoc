/**
 * Digest periódico del Centro de Acción por Telegram: avisa de los pendientes
 * (de TODOS los módulos, no solo SOAR) para que nadie tenga que mirar la app.
 * Anti-spam: no repite el mismo backlog sin cambios más de 1 vez/día.
 */
import cron from 'node-cron';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { sendTelegram, isTelegramConfigured } from '../notifications/telegram.service';
import { getActionQueue, type ActionItem } from './action-center.service';

const SRC_LABEL: Record<string, string> = { soar: 'SOAR', red: 'Red', identidad: 'Identidad', incidente: 'Incidente', endpoint: 'Endpoint' };
const SEV_EMOJI: Record<string, string> = { alta: '🔴', media: '🟠', baja: '🟢' };

// Limpia caracteres que romperían el parse Markdown de Telegram.
const clean = (s: string): string => String(s).replace(/[*_`[\]]/g, '').slice(0, 70);

let lastSig = '';
let lastSentAt = 0;

function sigOf(items: ActionItem[]): string {
  return items.map((i) => i.key).sort().join('|');
}

async function tick(): Promise<void> {
  if (!isTelegramConfigured() || !env.TELEGRAM_CHAT_ID) return;
  let q;
  try { q = await getActionQueue(); } catch { return; }
  if (q.total === 0) { lastSig = ''; return; } // cola vacía → silencio

  const sig = sigOf(q.items);
  const now = Date.now();
  // No re-molestar con el MISMO backlog sin cambios más de una vez al día.
  if (sig === lastSig && now - lastSentAt < 24 * 3600_000) return;

  const top = q.items.slice(0, 6).map((i) => `${SEV_EMOJI[i.severity] ?? ''} [${SRC_LABEL[i.source] ?? i.source}] ${clean(i.title)} · ${clean(i.subject)}`);
  const text = [
    '🛡️ *HexWatch · Centro de Acción*',
    `Tienes *${q.total}* acción(es) pendientes:  🔴 ${q.bySeverity.alta} · 🟠 ${q.bySeverity.media} · 🟢 ${q.bySeverity.baja}`,
    ...top,
    q.total > top.length ? `… y ${q.total - top.length} más.` : '',
    'Ábrelo en HexWatch → Centro de Acción.',
  ].filter(Boolean).join('\n');

  try {
    await sendTelegram([env.TELEGRAM_CHAT_ID], text);
    lastSig = sig; lastSentAt = now;
  } catch (err) {
    logger.warn({ err: err instanceof Error ? err.message : err }, 'Digest Centro de Acción: fallo al enviar por Telegram');
  }
}

/** Programa el digest (por defecto cada 6 h; configurable con ACTION_DIGEST_CRON). */
export function startActionDigestScheduler(): void {
  const schedule = env.ACTION_DIGEST_CRON || '0 */6 * * *';
  if (!cron.validate(schedule)) {
    logger.warn({ schedule }, 'ACTION_DIGEST_CRON inválido; usando cada 6h');
    cron.schedule('0 */6 * * *', () => void tick());
    return;
  }
  cron.schedule(schedule, () => void tick());
}
