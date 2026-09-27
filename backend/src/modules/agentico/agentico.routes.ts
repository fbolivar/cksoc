/**
 * Rutas de Agentico (analista SOC autónomo) + scheduler.
 *   POST /api/agentico/run      -> ejecuta un ciclo real (bloquea + envía Telegram)
 *   POST /api/agentico/preview  -> dry-run: analiza y devuelve el mensaje, sin actuar ni enviar
 */
import { Router, type Request, type Response } from 'express';
import cron from 'node-cron';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { requireRole } from '../../middleware/roles';
import { runAgenticoCycle, runUrgentWatch } from './agentico.service';

export const agenticoRouter = Router();

function handle(err: unknown, res: Response): void {
  const msg = err instanceof Error ? err.message : 'error';
  res.status(500).json({ error: msg });
}

agenticoRouter.post('/run', requireRole('admin'), async (_req: Request, res: Response) => {
  try { res.json(await runAgenticoCycle()); } catch (err) { handle(err, res); }
});

agenticoRouter.post('/preview', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try { res.json(await runAgenticoCycle({ dryRun: true })); } catch (err) { handle(err, res); }
});

/** Motor de Agentico: corre cada AGENTICO_INTERVAL_MIN minutos. */
export function startAgenticoScheduler(): void {
  if (!env.AGENTICO_ENABLED) {
    logger.info('Agentico: deshabilitado (AGENTICO_ENABLED=false)');
    return;
  }
  const min = Math.max(5, Math.min(1440, env.AGENTICO_INTERVAL_MIN));
  const spec = (min >= 60 && min % 60 === 0) ? `0 */${min / 60} * * *` : `*/${min} * * * *`;
  cron.schedule(spec, () => {
    runAgenticoCycle()
      .then((s) => logger.info({ acciones: s.acciones.length, telegram: s.telegram }, 'Agentico: ciclo completado'))
      .catch((err) => logger.warn({ err: err instanceof Error ? err.message : err }, 'Agentico: fallo en el ciclo'));
  });
  logger.info(`Agentico: activo cada ${min} min (autoblock=${env.AGENTICO_AUTOBLOCK})`);
}

/** Vigilante urgente de Agentico: revisa cada AGENTICO_URGENT_MIN min y reporta al instante lo crítico. */
export function startAgenticoUrgentWatch(): void {
  if (!env.AGENTICO_ENABLED) return;
  const min = Math.max(2, Math.min(60, env.AGENTICO_URGENT_MIN));
  cron.schedule(`*/${min} * * * *`, () => {
    runUrgentWatch()
      .then((r) => { if (r.enviado) logger.warn({ urgentes: r.urgentes }, 'Agentico: ALERTA URGENTE enviada'); })
      .catch((err) => logger.warn({ err: err instanceof Error ? err.message : err }, 'Agentico: fallo vigilante urgente'));
  });
  logger.info(`Agentico: vigilante urgente cada ${min} min (nivel>=${env.AGENTICO_URGENT_LEVEL})`);
}
