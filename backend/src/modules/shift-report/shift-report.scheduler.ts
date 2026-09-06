/**
 * Programador del Parte de Estado: dos cortes diarios (mañana/tarde).
 * APAGADO por defecto: solo corre si SHIFT_REPORT_ENABLED=true. Mientras esté
 * apagado, el parte se dispara manualmente desde la app (botón "Enviar parte").
 * Zona horaria y horas configurables por env.
 */
import cron from 'node-cron';
import { sendShiftReport } from './shift-report.service';
import { logger } from '../../config/logger';

export function startShiftReportScheduler(): void {
  const enabled = String(process.env.SHIFT_REPORT_ENABLED || 'false').toLowerCase() === 'true';
  if (!enabled) {
    logger.info('Parte de estado: programador APAGADO (SHIFT_REPORT_ENABLED!=true). Disponible solo por botón manual.');
    return;
  }
  const tz = process.env.SHIFT_REPORT_TZ || process.env.DIGEST_TZ || 'America/Bogota';
  const amCron = process.env.SHIFT_REPORT_AM_CRON || '0 9 * * *';
  const pmCron = process.env.SHIFT_REPORT_PM_CRON || '0 15 * * *';

  for (const [label, expr, turno] of [
    ['mañana', amCron, 'am'],
    ['tarde', pmCron, 'pm'],
  ] as const) {
    if (!cron.validate(expr)) {
      logger.error({ expr }, `Parte de estado: cron inválido para el turno ${label}`);
      continue;
    }
    cron.schedule(
      expr,
      () => {
        void sendShiftReport(turno)
          .then((r) => logger.info({ turno, internal: r.internal, chats: r.sentTo.length }, `Parte de estado (${label}) enviado`))
          .catch((err) => logger.error({ err, turno }, `Parte de estado (${label}) falló`));
      },
      { timezone: tz }
    );
    logger.info({ expr, tz }, `Parte de estado: turno ${label} programado`);
  }
}
