/**
 * Servicio del INFORME GERENCIAL de seguridad.
 *
 * Genera el informe para un periodo arbitrario (mes, trimestre, año o rango de
 * fechas), permite editar cada seccion antes de publicarlo, lo exporta a PDF y
 * lo envia al comite. Archiva ademas el snapshot mensual para las tendencias.
 */
import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync } from 'node:fs';
import { join, resolve, isAbsolute } from 'node:path';
import { query } from '../../../config/db';
import { env } from '../../../config/env';
import { HttpError } from '../../auth/auth.service';
import { htmlToPdf } from '../pdf.service';
import { sendEmail, isEmailConfigured } from '../../notifications/email.service';
import { getSettings } from '../../notifications/notify.engine';
import { collectMetrics, saveSnapshot, type ReportMetrics } from './exec.data';
import {
  buildExecutiveHtml, executiveEmailHtml, textosPorDefecto, resumenEjecutivo,
  type SeccionesEditables, type TextosInforme,
} from './exec.template';
import { resolvePeriodo, PeriodoInvalido, type Periodo } from './periodo';

const DIR = isAbsolute(env.REPORT_DIR) ? env.REPORT_DIR : resolve(process.cwd(), env.REPORT_DIR);

/** Nombre de la organizacion que aparece en el informe. */
const ORG = process.env.REPORT_ORG_NAME?.trim() || 'la organización';

export interface ExecReport {
  id: string;
  mes: string;
  desde: string | null;
  hasta: string | null;
  periodo_label: string | null;
  estado: 'borrador' | 'revisado' | 'enviado';
  pdf_path: string | null;
  datos_json: ReportMetrics;
  secciones: SeccionesEditables;
  resumen_editado: string | null;
  recomendaciones_editadas: string | null;
  generado_en: string;
  enviado_en: string | null;
}

export type ExecReportRef = Omit<ExecReport, 'datos_json' | 'secciones'>;

/** Claves de seccion aceptadas desde la API. */
export const CLAVES_SECCION = [
  'resumen', 'introduccion', 'objetivos', 'alcance', 'resultados',
  'analisis', 'conclusiones', 'recomendaciones', 'planAccion', 'hojaRuta', 'novedades',
] as const;
export type ClaveSeccion = (typeof CLAVES_SECCION)[number];

// --------------------------------------------------------------------------

/**
 * Combina las secciones editadas guardadas con los campos legados
 * (resumen_editado / recomendaciones_editadas) de la version anterior.
 */
function overridesOf(r: ExecReport): SeccionesEditables {
  const s: SeccionesEditables = { ...(r.secciones ?? {}) };
  if (!s.resumen && r.resumen_editado) s.resumen = r.resumen_editado;
  if (!s.recomendaciones && r.recomendaciones_editadas) s.recomendaciones = r.recomendaciones_editadas;
  return s;
}

/**
 * Los informes creados con la version anterior del modulo guardaron un
 * `datos_json` con otra forma (sin periodo, gestion ni cobertura) y no se
 * pueden volver a renderizar. Su PDF sigue disponible para descarga.
 */
function assertRenderizable(r: ExecReport): void {
  if (!r.datos_json || typeof r.datos_json !== 'object' || !r.datos_json.periodo) {
    throw new HttpError(
      409,
      'Este informe se generó con una versión anterior del módulo. Su PDF sigue disponible para descarga; para verlo con el nuevo formato, genera uno nuevo con el mismo periodo.'
    );
  }
}

function renderHtml(r: ExecReport): string {
  assertRenderizable(r);
  return buildExecutiveHtml(r.datos_json, overridesOf(r), { organizacion: ORG });
}

async function renderPdf(r: ExecReport): Promise<string> {
  if (!existsSync(DIR)) mkdirSync(DIR, { recursive: true });
  const pdf = await htmlToPdf(renderHtml(r));
  const path = join(DIR, `informe-gerencial-${r.desde ?? r.mes}_${r.hasta ?? ''}-${r.id}.pdf`);
  writeFileSync(path, pdf);
  return path;
}

// --------------------------------------------------------------------------

/**
 * Genera el informe de un periodo. Acepta un preset ('mes-anterior',
 * 'trimestre-actual', ...) o un rango explicito desde/hasta (AAAA-MM-DD).
 */
export async function generate(
  entrada: { preset?: string; desde?: string; hasta?: string } | string,
  userId: string | null
): Promise<ExecReport> {
  let periodo: Periodo;
  try {
    if (typeof entrada === 'string') {
      // Compatibilidad: "YYYY-MM" => ese mes completo
      if (!/^\d{4}-\d{2}$/.test(entrada)) throw new PeriodoInvalido('Mes inválido (formato AAAA-MM)');
      const [y, m] = entrada.split('-').map(Number);
      const fin = new Date(Date.UTC(y, m, 0)).getUTCDate();
      periodo = resolvePeriodo({ desde: `${entrada}-01`, hasta: `${entrada}-${String(fin).padStart(2, '0')}` });
    } else {
      periodo = resolvePeriodo(entrada);
    }
  } catch (e) {
    throw new HttpError(400, e instanceof PeriodoInvalido ? e.message : 'Periodo inválido');
  }

  const metrics = await collectMetrics(periodo);

  const rows = await query<{ id: string }>(
    `INSERT INTO executive_reports (mes, desde, hasta, periodo_label, estado, datos_json, secciones, generado_por)
     VALUES ($1,$2,$3,$4,'borrador',$5::jsonb,'{}'::jsonb,$6) RETURNING id`,
    [periodo.mes, periodo.desde, periodo.hasta, periodo.label, JSON.stringify(metrics), userId]
  );
  const id = rows[0].id;
  const report = await getReport(id);
  const path = await renderPdf(report);
  await query('UPDATE executive_reports SET pdf_path=$1 WHERE id=$2', [path, id]);

  await saveSnapshot(metrics); // solo archiva si el periodo es un mes completo
  return getReport(id);
}

/** Guarda las secciones editadas y regenera el PDF (estado -> revisado). */
export async function updateTexts(id: string, data: Partial<Record<ClaveSeccion, string>>): Promise<ExecReport> {
  const cur = await getReport(id);
  const merged: SeccionesEditables = { ...overridesOf(cur) };
  for (const k of CLAVES_SECCION) {
    const v = data[k];
    if (v === undefined) continue;
    // Cadena vacia => volver al texto generado automaticamente
    (merged as Record<string, string | null>)[k] = v.trim() === '' ? null : v;
  }
  await query(
    `UPDATE executive_reports SET secciones=$2::jsonb,
       estado = CASE WHEN estado='enviado' THEN estado ELSE 'revisado' END
     WHERE id=$1`,
    [id, JSON.stringify(merged)]
  );
  const updated = await getReport(id);
  const path = await renderPdf(updated);
  await query('UPDATE executive_reports SET pdf_path=$1 WHERE id=$2', [path, id]);
  return getReport(id);
}

/** Marca el informe como aprobado para envio. */
export async function marcarRevisado(id: string): Promise<ExecReport> {
  await query(`UPDATE executive_reports SET estado='revisado' WHERE id=$1 AND estado='borrador'`, [id]);
  return getReport(id);
}

/** Envia el informe al comite (manual, tras revision). Usa el SMTP configurado. */
export async function sendToCommittee(id: string): Promise<{ recipients: string[] }> {
  if (!isEmailConfigured()) throw new HttpError(503, 'SMTP no configurado');
  const r = await getReport(id);
  assertRenderizable(r);
  const settings = await getSettings();
  if (settings.recipients.length === 0) throw new HttpError(400, 'No hay destinatarios configurados');
  if (!r.pdf_path || !existsSync(r.pdf_path)) throw new HttpError(404, 'El PDF del informe no está disponible');

  const ov = overridesOf(r);
  const resumen = ov.resumen || resumenEjecutivo(r.datos_json);
  const html = executiveEmailHtml(r.datos_json, resumen);
  const pdf = readFileSync(r.pdf_path);
  const nombre = nombreArchivo(r);
  const subject = `[HexWatch] Informe Gerencial de Seguridad — ${r.datos_json.periodoLabel}`;
  await sendEmail(
    settings.recipients, subject, html,
    `Informe gerencial de seguridad — ${r.datos_json.periodoLabel} (PDF adjunto)`,
    [{ filename: nombre, content: pdf, contentType: 'application/pdf' }]
  );

  await query(`UPDATE executive_reports SET estado='enviado', enviado_en=now() WHERE id=$1`, [id]);
  return { recipients: settings.recipients };
}

export async function getReport(id: string): Promise<ExecReport> {
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new HttpError(404, 'Informe no encontrado');
  const rows = await query<ExecReport>(
    `SELECT id, mes, to_char(desde,'YYYY-MM-DD') AS desde, to_char(hasta,'YYYY-MM-DD') AS hasta,
            periodo_label, estado, pdf_path, datos_json, COALESCE(secciones,'{}'::jsonb) AS secciones,
            resumen_editado, recomendaciones_editadas, generado_en, enviado_en
       FROM executive_reports WHERE id=$1`,
    [id]
  );
  if (rows.length === 0) throw new HttpError(404, 'Informe no encontrado');
  return rows[0];
}

/**
 * Vista previa: HTML renderizado + textos de cada seccion (el editado si
 * existe, si no el generado automaticamente) para alimentar el editor.
 */
export function preview(r: ExecReport): {
  html: string;
  textos: TextosInforme;
  editadas: ClaveSeccion[];
  // compatibilidad con la version anterior del frontend
  resumen: string;
  recomendaciones: string;
} {
  assertRenderizable(r);
  const ov = overridesOf(r);
  const base = textosPorDefecto(r.datos_json, ORG);
  const textos = { ...base } as TextosInforme;
  const editadas: ClaveSeccion[] = [];
  for (const k of CLAVES_SECCION) {
    const v = ov[k];
    if (typeof v === 'string' && v.trim() !== '') {
      textos[k] = v;
      editadas.push(k);
    }
  }
  return {
    html: renderHtml(r),
    textos,
    editadas,
    resumen: textos.resumen,
    recomendaciones: textos.recomendaciones,
  };
}

export async function listReports(limit = 50): Promise<ExecReportRef[]> {
  return query<ExecReportRef>(
    `SELECT id, mes, to_char(desde,'YYYY-MM-DD') AS desde, to_char(hasta,'YYYY-MM-DD') AS hasta,
            periodo_label, estado, pdf_path, resumen_editado, recomendaciones_editadas,
            generado_en, enviado_en
       FROM executive_reports ORDER BY generado_en DESC LIMIT $1`,
    [limit]
  );
}

export async function getReportFile(id: string): Promise<string> {
  const r = await getReport(id);
  if (!r.pdf_path || !existsSync(r.pdf_path)) throw new HttpError(404, 'PDF no disponible');
  return r.pdf_path;
}

export async function deleteReport(id: string): Promise<void> {
  const r = await getReport(id);
  if (r.pdf_path && existsSync(r.pdf_path)) {
    try { unlinkSync(r.pdf_path); } catch { /* el registro se borra igual */ }
  }
  await query('DELETE FROM executive_reports WHERE id=$1', [id]);
}

/** Nombre de archivo del PDF para la descarga. */
export function nombreArchivo(r: ExecReport | ExecReportRef): string {
  const p = r.desde && r.hasta ? `${r.desde}_a_${r.hasta}` : r.mes;
  return `Informe-Gerencial-Seguridad-${p}.pdf`;
}
