/**
 * Servicio del INFORME TECNICO del SOC: generacion, persistencia en disco +
 * report_history, listado, vista previa, descarga y borrado.
 *
 * El informe se genera para un periodo arbitrario (preset o rango de fechas).
 * Las metricas quedan guardadas en `datos_json` para poder re-renderizar la
 * vista previa sin volver a consultar el Indexer.
 */
import { existsSync, mkdirSync, writeFileSync, unlinkSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { query } from '../../config/db';
import { env } from '../../config/env';
import { HttpError } from '../auth/auth.service';
import { collectTechMetrics, type TechMetrics } from './tecnico/tech.data';
import { buildTechnicalHtml } from './tecnico/tech.template';
import { htmlToPdf } from './pdf.service';
import { resolvePeriodo, PeriodoInvalido, type Periodo } from './executive/periodo';

const REPORT_DIR = isAbsolute(env.REPORT_DIR) ? env.REPORT_DIR : resolve(process.cwd(), env.REPORT_DIR);

export interface ReportRow {
  id: string;
  title: string;
  type: string;
  format: string;
  file_path: string | null;
  params: { preset?: string; desde?: string; hasta?: string; label?: string; range?: string };
  status: string;
  created_at: string;
}

interface ReportRowConDatos extends ReportRow {
  datos_json: TechMetrics | null;
}

function ensureDir(): void {
  if (!existsSync(REPORT_DIR)) mkdirSync(REPORT_DIR, { recursive: true });
}

/** Rangos del flujo anterior mapeados a presets del nuevo resolutor. */
const RANGO_LEGADO: Record<string, string> = {
  '24h': 'ultimas-24h',
  '7d': 'ultimos-7d',
  '30d': 'ultimos-30d',
};

/** Resuelve el periodo a partir de la entrada de la API (o del rango legado). */
export function periodoDeEntrada(input: {
  preset?: string; desde?: string; hasta?: string; range?: string;
}): Periodo {
  try {
    if (input.desde && input.hasta) {
      return resolvePeriodo({ preset: input.preset ?? 'personalizado', desde: input.desde, hasta: input.hasta });
    }
    const preset = input.preset ?? RANGO_LEGADO[input.range ?? ''] ?? 'ultimas-24h';
    return resolvePeriodo({ preset });
  } catch (e) {
    throw new HttpError(400, e instanceof PeriodoInvalido ? e.message : 'Periodo inválido');
  }
}

/** Genera el informe tecnico en PDF, lo guarda y lo registra en el historial. */
export async function generateReport(opts: {
  title: string;
  periodo: Periodo;
  type: 'manual' | 'scheduled';
  userId: string | null;
}): Promise<ReportRow> {
  ensureDir();
  const metrics = await collectTechMetrics(opts.periodo, opts.title);
  const pdf = await htmlToPdf(buildTechnicalHtml(metrics));

  const params = {
    preset: opts.periodo.preset,
    desde: opts.periodo.desde,
    hasta: opts.periodo.hasta,
    label: opts.periodo.label,
  };
  const rows = await query<{ id: string }>(
    `INSERT INTO report_history (title, type, format, params, status, generated_by, datos_json)
     VALUES ($1, $2, 'pdf', $3::jsonb, 'completed', $4, $5::jsonb) RETURNING id`,
    [opts.title, opts.type, JSON.stringify(params), opts.userId, JSON.stringify(metrics)]
  );
  const id = rows[0].id;
  const filePath = join(REPORT_DIR, `informe-tecnico-${opts.periodo.desde}_${opts.periodo.hasta}-${id}.pdf`);
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
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new HttpError(404, 'Reporte no encontrado');
  const rows = await query<ReportRow>(
    `SELECT id, title, type, format, file_path, params, status, created_at
       FROM report_history WHERE id = $1`,
    [id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Reporte no encontrado');
  return rows[0];
}

/**
 * HTML del informe para vista previa en la aplicacion. Se re-renderiza a
 * partir de las metricas archivadas: no vuelve a consultar el Indexer.
 */
export async function getReportHtml(id: string): Promise<{ html: string; title: string }> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new HttpError(404, 'Reporte no encontrado');
  const rows = await query<ReportRowConDatos>(
    `SELECT id, title, type, format, file_path, params, status, created_at, datos_json
       FROM report_history WHERE id = $1`,
    [id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Reporte no encontrado');
  const r = rows[0];
  if (!r.datos_json || !r.datos_json.periodo) {
    throw new HttpError(
      409,
      'Este reporte se generó con una versión anterior del módulo y no tiene vista previa. Su PDF sigue disponible para descarga.'
    );
  }
  return { html: buildTechnicalHtml(r.datos_json), title: r.title };
}

/** Ruta del PDF para descarga (valida que exista). */
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
