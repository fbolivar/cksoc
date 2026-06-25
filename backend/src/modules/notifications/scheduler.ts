/**
 * Programador de tareas (node-cron).
 * - Cada minuto: evalua las reglas de notificacion.
 * Preparado para anadir reportes programados en la Fase 4.
 */
import cron from 'node-cron';
import { evaluateRules } from './evaluator';

let running = false;

export function startScheduler(): void {
  // Cada minuto
  cron.schedule('* * * * *', async () => {
    if (running) return; // evita solapamiento si una corrida tarda
    running = true;
    try {
      await evaluateRules();
    } finally {
      running = false;
    }
  });
  // eslint-disable-next-line no-console
  console.log('🕒 Scheduler de notificaciones activo (evaluacion cada minuto)');
}
