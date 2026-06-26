/**
 * Servicio del reporte ejecutivo mensual: generar (PDF + preview), editar
 * textos, enviar al comite (manual) e historial. Archiva snapshot mensual.
 */
import { existsSync, mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { query } from '../../../config/db';
import { env } from '../../../config/env';
import { HttpError } from '../../auth/auth.service';
import { htmlToPdf } from '../pdf.service';
import { sendEmail, isEmailConfigured } from '../../notifications/email.service';
import { getSettings } from '../../notifications/notify.engine';
import { collectMetrics, saveSnapshot, type ReportMetrics } from './exec.data';
import { buildExecutiveHtml, executiveEmailHtml, defaultSummary, defaultRecommendations } from './exec.template';

const DIR = isAbsolute(env.REPORT_DIR) ? env.REPORT_DIR : resolve(process.cwd(), env.REPORT_DIR);

export interface ExecReport {
  id: string;
  mes: string;
  estado: 'borrador' | 'revisado' | 'enviado';
  pdf_path: string | null;
  datos_json: ReportMetrics;
  resumen_editado: string | null;
  recomendaciones_editadas: string | null;
  generado_en: string;
  enviado_en: string | null;
}

function overridesOf(r: ExecReport) {
  return { resumen: r.resumen_editado, recomendaciones: r.recomendaciones_editadas };
}

async function renderPdf(r: ExecReport): Promise<string> {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
  const html = buildExecutiveHtml(r.datos_json, overridesOf(r));
  const pdf = await htmlToPdf(html);
  const path = join(DIR, `executive-${r.mes}-${r.id}.pdf`);
  writeFileSync(path, pdf);
  return path;
}

/** Genera el reporte de un mes: recopila datos, crea PDF, guarda y archiva snapshot. */
export async function generate(mes: string, userId: string | null): Promise<ExecReport> {
  if (!/^\d{4}-\d{2}$/.test(mes)) throw new HttpError(400, 'Mes invalido (formato YYYY-MM)');
  const metrics = await collectMetrics(mes);

  const rows = await query<{ id: string }>(
    `INSERT INTO executive_reports (mes, estado, datos_json, generado_por)
     VALUES ($1,'borrador',$2::jsonb,$3) RETURNING id`,
    [mes, JSON.stringify(metrics), userId]
  );
  const id = rows[0].id;
  const report = await getReport(id);
  const path = await renderPdf(report);
  await query('UPDATE executive_reports SET pdf_path=$1 WHERE id=$2', [path, id]);

  await saveSnapshot(metrics); // archiva para tendencias futuras
  return getReport(id);
}

/** Edita el resumen/recomendaciones y regenera el PDF (estado -> revisado). */
export async function updateTexts(
  id: string,
  data: { resumen?: string; recomendaciones?: string }
): Promise<ExecReport> {
  const cur = await getReport(id);
  await query(
    `UPDATE executive_reports SET
       resumen_editado = COALESCE($2, resumen_editado),
       recomendaciones_editadas = COALESCE($3, recomendaciones_editadas),
       estado = CASE WHEN estado='enviado' THEN estado ELSE 'revisado' END
     WHERE id=$1`,
    [id, data.resumen ?? null, data.recomendaciones ?? null]
  );
  const updated = await getReport(id);
  const path = await renderPdf(updated);
  await query('UPDATE executive_reports SET pdf_path=$1 WHERE id=$2', [path, id]);
  void cur;
  return getReport(id);
}

/** Envia el reporte al comite (manual, tras revision). Usa el SMTP configurado. */
export async function sendToCommittee(id: string): Promise<{ recipients: string[] }> {
  if (!isEmailConfigured()) throw new HttpError(503, 'SMTP no configurado');
  const r = await getReport(id);
  const settings = await getSettings();
  if (settings.recipients.length === 0) throw new HttpError(400, 'No hay destinatarios configurados');
  if (!r.pdf_path || !existsSync(r.pdf_path)) throw new HttpError(404, 'El PDF del reporte no esta disponible');

  const resumen = r.resumen_editado || defaultSummary(r.datos_json);
  const html = executiveEmailHtml(r.datos_json, resumen);
  const pdf = readFileSync(r.pdf_path);
  const subject = `[SOC PNNC] Reporte Ejecutivo de Seguridad - ${r.datos_json.periodoLabel}`;
  await sendEmail(settings.recipients, subject, html,
    `Reporte ejecutivo de seguridad - ${r.datos_json.periodoLabel} (PDF adjunto)`,
    [{ filename: `Reporte-Ejecutivo-${r.mes}.pdf`, content: pdf, contentType: 'application/pdf' }]);

  await query(`UPDATE executive_reports SET estado='enviado', enviado_en=now() WHERE id=$1`, [id]);
  return { recipients: settings.recipients };
}

export async function getReport(id: string): Promise<ExecReport> {
  const rows = await query<ExecReport>(
    `SELECT id, mes, estado, pdf_path, datos_json, resumen_editado, recomendaciones_editadas,
            generado_en, enviado_en FROM executive_reports WHERE id=$1`,
    [id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Reporte ejecutivo no encontrado');
  return rows[0];
}

/** Devuelve el HTML de previsualizacion + textos editables actuales. */
export function preview(r: ExecReport): { html: string; resumen: string; recomendaciones: string } {
  return {
    html: buildExecutiveHtml(r.datos_json, overridesOf(r)),
    resumen: r.resumen_editado || defaultSummary(r.datos_json),
    recomendaciones: r.recomendaciones_editadas || defaultRecommendations(r.datos_json),
  };
}

export async function listReports(): Promise<Omit<ExecReport, 'datos_json'>[]> {
  return query(
    `SELECT id, mes, estado, pdf_path, resumen_editado, recomendaciones_editadas, generado_en, enviado_en
       FROM executive_reports ORDER BY generado_en DESC LIMIT 50`
  );
}

export async function getReportFile(id: string): Promise<string> {
  const r = await getReport(id);
  if (!r.pdf_path || !existsSync(r.pdf_path)) throw new HttpError(404, 'PDF no disponible');
  return r.pdf_path;
}
