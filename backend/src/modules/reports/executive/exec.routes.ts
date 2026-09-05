/**
 * Rutas del INFORME GERENCIAL de seguridad. Solo rol ADMIN.
 *   GET    /api/reports/executive/presets       periodos disponibles
 *   POST   /api/reports/executive/generate      { preset } o { desde, hasta } (o { mes } legado)
 *   GET    /api/reports/executive/history       historial
 *   GET    /api/reports/executive/:id           vista previa + textos editables
 *   PUT    /api/reports/executive/:id           guardar ediciones por seccion
 *   POST   /api/reports/executive/:id/send      enviar al comite
 *   GET    /api/reports/executive/:id/download  descargar PDF
 *   DELETE /api/reports/executive/:id           eliminar
 */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { authenticate } from '../../../middleware/auth';
import { requireRole } from '../../../middleware/roles';
import { HttpError } from '../../auth/auth.service';
import {
  generate, updateTexts, sendToCommittee, getReport, preview, listReports,
  getReportFile, deleteReport, marcarRevisado, nombreArchivo,
} from './exec.report.service';
import { PRESETS } from './periodo';

export const executiveRouter = Router();
executiveRouter.use(authenticate, requireRole('admin'));

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  // eslint-disable-next-line no-console
  console.error('Error en informe gerencial:', err);
  res.status(500).json({ error: 'Error generando el informe gerencial' });
}

/** Periodos predefinidos que ofrece la interfaz. */
executiveRouter.get('/presets', (_req, res) => {
  res.json({ presets: PRESETS });
});

const genSchema = z.object({
  preset: z.string().max(40).optional(),
  desde: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  hasta: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  mes: z.string().regex(/^\d{4}-\d{2}$/).optional(),   // compatibilidad
});

executiveRouter.post('/generate', async (req: Request, res: Response) => {
  const parsed = genSchema.safeParse(req.body ?? {});
  if (!parsed.success) { res.status(400).json({ error: 'Parámetros de periodo inválidos' }); return; }
  const { preset, desde, hasta, mes } = parsed.data;
  try {
    const report = mes && !preset && !desde
      ? await generate(mes, req.user!.id)
      : await generate({ preset, desde, hasta }, req.user!.id);
    res.status(201).json({ report: ref(report), ...preview(report) });
  } catch (err) { handle(err, res); }
});

executiveRouter.get('/history', async (_req, res) => {
  try {
    const reports = await listReports();
    res.json({ reports: reports.map(ref) });
  } catch (err) { handle(err, res); }
});

executiveRouter.get('/:id', async (req, res) => {
  try {
    const r = await getReport(req.params.id);
    res.json({ report: ref(r), ...preview(r) });
  } catch (err) { handle(err, res); }
});

const texto = z.string().max(20_000).optional();
const editSchema = z.object({
  resumen: texto,
  introduccion: texto,
  objetivos: texto,
  alcance: texto,
  resultados: texto,
  analisis: texto,
  conclusiones: texto,
  recomendaciones: texto,
  planAccion: texto,
  hojaRuta: texto,
  novedades: texto,
});

executiveRouter.put('/:id', async (req, res) => {
  const parsed = editSchema.safeParse(req.body ?? {});
  if (!parsed.success) { res.status(400).json({ error: 'Datos inválidos' }); return; }
  try {
    const r = await updateTexts(req.params.id, parsed.data as Record<string, string>);
    res.json({ report: ref(r), ...preview(r) });
  } catch (err) { handle(err, res); }
});

executiveRouter.post('/:id/approve', async (req, res) => {
  try {
    const r = await marcarRevisado(req.params.id);
    res.json({ report: ref(r) });
  } catch (err) { handle(err, res); }
});

executiveRouter.post('/:id/send', async (req, res) => {
  try { res.json(await sendToCommittee(req.params.id)); } catch (err) { handle(err, res); }
});

executiveRouter.get('/:id/download', async (req, res) => {
  try {
    const path = await getReportFile(req.params.id);
    const r = await getReport(req.params.id);
    res.download(path, nombreArchivo(r));
  } catch (err) { handle(err, res); }
});

executiveRouter.delete('/:id', async (req, res) => {
  try { await deleteReport(req.params.id); res.json({ ok: true }); } catch (err) { handle(err, res); }
});

/** Referencia liviana del informe (sin metricas ni HTML). */
function ref(r: { id: string; mes: string; desde: string | null; hasta: string | null; periodo_label: string | null; estado: string; generado_en?: string; enviado_en: string | null }) {
  return {
    id: r.id, mes: r.mes, desde: r.desde, hasta: r.hasta,
    periodoLabel: r.periodo_label, estado: r.estado,
    generado_en: r.generado_en, enviado_en: r.enviado_en,
  };
}
