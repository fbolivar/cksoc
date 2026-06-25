/**
 * Reporte programado (node-cron).
 * Genera un reporte diario y, si hay SMTP + REPORT_EMAIL_TO, lo envia por correo.
 */
import cron from 'node-cron';
import { env } from '../../config/env';
import { generateReport } from './reports.service';
import { readFileSync } from 'node:fs';
import { sendEmail, isEmailConfigured } from '../notifications/email.service';

export function startReportScheduler(): void {
  if (!env.REPORT_SCHEDULE_ENABLED) {
    // eslint-disable-next-line no-console
    console.log('🗒️  Reporte programado deshabilitado');
    return;
  }
  if (!cron.validate(env.REPORT_SCHEDULE_CRON)) {
    console.error('Cron de reporte invalido:', env.REPORT_SCHEDULE_CRON);
    return;
  }

  cron.schedule(env.REPORT_SCHEDULE_CRON, async () => {
    try {
      const fecha = new Date().toLocaleDateString('es-CO');
      const report = await generateReport({
        title: `Reporte de seguridad SOC PNNC · ${fecha}`,
        range: env.REPORT_SCHEDULE_RANGE,
        type: 'scheduled',
        userId: null,
      });
      // eslint-disable-next-line no-console
      console.log(`📄 Reporte programado generado: ${report.id}`);

      // Envio opcional por correo
      const to = (env.REPORT_EMAIL_TO ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (to.length > 0 && isEmailConfigured() && report.file_path) {
        const pdf = readFileSync(report.file_path);
        await sendEmail(
          to,
          report.title,
          `<p>Adjunto el <b>${report.title}</b> generado automáticamente por el SOC de PNNC.</p>`,
          `${report.title} (adjunto PDF)`,
          [{ filename: `${report.title}.pdf`, content: pdf, contentType: 'application/pdf' }]
        ).catch((e) => console.error('No se pudo enviar el reporte por correo:', e?.message));
      }
    } catch (err) {
      console.error('Error en reporte programado:', err instanceof Error ? err.message : err);
    }
  });
  // eslint-disable-next-line no-console
  console.log(`🗒️  Reporte programado activo (${env.REPORT_SCHEDULE_CRON}, rango ${env.REPORT_SCHEDULE_RANGE})`);
}
