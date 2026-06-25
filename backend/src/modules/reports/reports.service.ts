/**
 * Servicio de reportes PDF: generacion, persistencia en disco + report_history,
 * listado, descarga y borrado.
 */
import { readFileSync, existsSync, mkdirSync, writeFileSync, unlinkSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { collectReportData } from './report.data';
import { buildReportHtml } from './report.template';
import { htmlToPdf } from './pdf.service';

const REPORT_DIR = isAbsolute(env.REPORT_DIR) ? env.REPORT_DIR : resolve(process.cwd(), env.REPORT_DIR);

// Logo PNNC embebido (si existe) para PDFs autocontenidos
function logoDataUri(): string | undefined {
  const candidates = [
    resolve(process.cwd(), '../frontend/public/logo-pnnc.png'),
    resolve(process.cwd(), 'assets/logo-pnnc.png'),
  ];
  for (const p of candidates) {
    if (existsSync(p)) {
      return `data:image/png;base64,${readFileSync(p).toString('base64')}`;
    }
  }
  return undefined;
}

export interface ReportRow {
  id: string;
  title: string;
  type: string;
  format: string;
  file_path: string | null;
  params: { range?: string };
  status: string;
  created_at: string;
}

function ensureDir(): void {
  if (!existsSync(REPORT_DIR)) mkdirSync(REPORT_DIR, { recursive: true });
}

/** Genera un reporte PDF, lo guarda en disco y registra en report_history. */
export async function generateReport(opts: {
  title: string;
  range: string;
  type: 'manual' | 'scheduled';
  userId: string | null;
}): Promise<ReportRow> {
  ensureDir();
  const data = await collectReportData(opts.range);
  const html = buildReportHtml(data, { title: opts.title, logoDataUri: logoDataUri() });
  const pdf = await htmlToPdf(html);

  // Inserta primero para obtener el id y nombrar el archivo
  const rows = await query<{ id: string }>(
    `INSERT INTO report_history (title, type, format, params, status, generated_by)
     VALUES ($1, $2, 'pdf', $3::jsonb, 'completed', $4) RETURNING id`,
    [opts.title, opts.type, JSON.stringify({ range: opts.range }), opts.userId]
  );
  const id = rows[0].id;
  const filePath = join(REPORT_DIR, `report-${id}.pdf`);
  writeFileSync(filePath, pdf);
  await query('UPDATE report_history SET file_path = $1 WHERE id = $2', [filePath, id]);

  return getReport(id);
}

export async function listReports(limit = 50): Promise<ReportRow[]> {
  return query<ReportRow>(
    `SELECT id, title, type, format, file_path, params, status, created_at
       FROM report_history ORDER BY created_at DESC LIMIT $1`,
    [limit]
  );
}

export async function getReport(id: string): Promise<ReportRow> {
  const rows = await query<ReportRow>(
    `SELECT id, title, type, format, file_path, params, status, created_at
       FROM report_history WHERE id = $1`,
    [id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Reporte no encontrado');
  return rows[0];
}

/** Devuelve la ruta del archivo PDF para descarga (valida que exista). */
export async function getReportFile(id: string): Promise<{ path: string; title: string }> {
  const r = await getReport(id);
  if (!r.file_path || !existsSync(r.file_path)) {
    throw new HttpError(404, 'El archivo del reporte no está disponible');
  }
  return { path: r.file_path, title: r.title };
}

export async function deleteReport(id: string): Promise<void> {
  const r = await getReport(id);
  if (r.file_path && existsSync(r.file_path)) {
    try {
      unlinkSync(r.file_path);
    } catch {
      /* el registro se borra igual */
    }
  }
  await query('DELETE FROM report_history WHERE id = $1', [id]);
}
