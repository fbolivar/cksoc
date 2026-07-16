/**
 * Respaldo automatico diario de la base de datos (node-cron).
 * Genera un .pnnc con origin 'automatico' y aplica retencion (BACKUP_RETENTION).
 */
import cron from 'node-cron';
import { env } from '../../config/env';
import { logger } from '../../config/logger';
import { createBackup, enforceRetention } from './backups.service';

export function startBackupScheduler(): void {
  if (!cron.validate(env.BACKUP_CRON)) {
    logger.error({ cron: env.BACKUP_CRON }, 'BACKUP_CRON invalido; respaldo automatico deshabilitado');
    return;
  }
  cron.schedule(env.BACKUP_CRON, async () => {
    try {
      const item = await createBackup({ origin: 'automatico', note: 'Respaldo automatico diario' });
      await enforceRetention(env.BACKUP_RETENTION);
      logger.info({ id: item.id, bytes: item.fileBytes }, 'Respaldo automatico completado');
    } catch (err) {
      logger.error({ err }, 'Fallo el respaldo automatico');
    }
  });
  logger.info({ cron: env.BACKUP_CRON, retencion: env.BACKUP_RETENTION }, 'Respaldo automatico programado');
}
