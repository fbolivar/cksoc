/**
 * Informe tecnico programado (node-cron).
 * Genera el informe del periodo configurado y, si hay SMTP + REPORT_EMAIL_TO,
 * lo envia por correo al equipo tecnico.
 */
import cron from 'node-cron';
import { env } from '../../config/env';
import { generateReport, periodoDeEntrada } from './reports.service';
import { readFileSync } from 'node:fs';
import { sendEmail, isEmailConfigured } from '../notifications/email.service';

export function startReportScheduler(): void {
  if (!env.REPORT_SCHEDULE_ENABLED) {
    // eslint-disable-next-line no-console
    console.log('🗒️  Informe técnico programado deshabilitado');
    return;
  }
  if (!cron.validate(env.REPORT_SCHEDULE_CRON)) {
    console.error('Cron de reporte invalido:', env.REPORT_SCHEDULE_CRON);
    return;
  }

  cron.schedule(env.REPORT_SCHEDULE_CRON, async () => {
    try {
      const periodo = periodoDeEntrada({ range: env.REPORT_SCHEDULE_RANGE });
      const title = `Informe técnico del SOC · ${periodo.label}`;
      const report = await generateReport({ title, periodo, type: 'scheduled', userId: null });
      // eslint-disable-next-line no-console
      console.log(`📄 Informe técnico programado generado: ${report.id}`);

      // Envio opcional por correo
      const to = (env.REPORT_EMAIL_TO ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      if (to.length > 0 && isEmailConfigured() && report.file_path) {
        const pdf = readFileSync(report.file_path);
        await sendEmail(
          to,
          title,
          `<p>Adjunto el <b>${title}</b>, generado automáticamente por el SOC de HexWatch.</p>
           <p style="color:#6b7280;font-size:12px">Incluye hallazgos priorizados con evidencia, plan de acción y hoja de ruta por sprints.</p>`,
          `${title} (adjunto PDF)`,
          [{ filename: `${title}.pdf`, content: pdf, contentType: 'application/pdf' }]
        ).catch((e) => console.error('No se pudo enviar el informe por correo:', e?.message));
      }
    } catch (err) {
      console.error('Error en informe técnico programado:', err instanceof Error ? err.message : err);
    }
  });
  // eslint-disable-next-line no-console
  console.log(`🗒️  Informe técnico programado activo (${env.REPORT_SCHEDULE_CRON}, rango ${env.REPORT_SCHEDULE_RANGE})`);
}
