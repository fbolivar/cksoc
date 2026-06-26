/**
 * Rutas del reporte ejecutivo mensual (Comite SGSI). Solo rol ADMIN.
 *   POST   /api/reports/executive/generate     { mes }
 *   GET    /api/reports/executive/history
 *   GET    /api/reports/executive/:id           preview + textos editables
 *   PUT    /api/reports/executive/:id           guardar ediciones (resumen/recom)
 *   POST   /api/reports/executive/:id/send       enviar al comite (manual)
 *   GET    /api/reports/executive/:id/download    descargar PDF
 */
import { Router, type Request, type Response } from 'express';
import { z } from 'zod';
import { authenticate } from '../../../middleware/auth';
import { requireRole } from '../../../middleware/roles';
import { HttpError } from '../../auth/auth.service';
import {
  generate, updateTexts, sendToCommittee, getReport, preview, listReports, getReportFile,
} from './exec.report.service';
import { currentMonth } from './exec.data';

export const executiveRouter = Router();
executiveRouter.use(authenticate, requireRole('admin'));

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  // eslint-disable-next-line no-console
  console.error('Error en reporte ejecutivo:', err);
  res.status(500).json({ error: 'Error generando el reporte ejecutivo' });
}

executiveRouter.post('/generate', async (req: Request, res: Response) => {
  const mes = typeof req.body?.mes === 'string' && /^\d{4}-\d{2}$/.test(req.body.mes) ? req.body.mes : currentMonth();
  try {
    const report = await generate(mes, req.user!.id);
    res.status(201).json({ report: { id: report.id, mes: report.mes, estado: report.estado }, ...preview(report) });
  } catch (err) { handle(err, res); }
});

executiveRouter.get('/history', async (_req, res) => {
  try { res.json({ reports: await listReports() }); } catch (err) { handle(err, res); }
});

executiveRouter.get('/:id', async (req, res) => {
  try {
    const r = await getReport(req.params.id);
    res.json({ report: { id: r.id, mes: r.mes, estado: r.estado, enviado_en: r.enviado_en }, ...preview(r) });
  } catch (err) { handle(err, res); }
});

const editSchema = z.object({ resumen: z.string().optional(), recomendaciones: z.string().optional() });
executiveRouter.put('/:id', async (req, res) => {
  const parsed = editSchema.safeParse(req.body);
  if (!parsed.success) { res.status(400).json({ error: 'Datos invalidos' }); return; }
  try {
    const r = await updateTexts(req.params.id, parsed.data);
    res.json({ report: { id: r.id, mes: r.mes, estado: r.estado }, ...preview(r) });
  } catch (err) { handle(err, res); }
});

executiveRouter.post('/:id/send', async (req, res) => {
  try { res.json(await sendToCommittee(req.params.id)); } catch (err) { handle(err, res); }
});

executiveRouter.get('/:id/download', async (req, res) => {
  try {
    const path = await getReportFile(req.params.id);
    const r = await getReport(req.params.id);
    res.download(path, `Reporte-Ejecutivo-${r.mes}.pdf`);
  } catch (err) { handle(err, res); }
});
