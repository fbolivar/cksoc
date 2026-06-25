/** Controladores del modulo de reportes. */
import type { Request, Response } from 'express';
import { z } from 'zod';
import {
  generateReport,
  listReports,
  getReportFile,
  deleteReport,
} from './reports.service';
import { HttpError } from '../auth/auth.service';

const genSchema = z.object({
  title: z.string().min(2).max(200),
  range: z.enum(['24h', '7d', '30d']).default('24h'),
});

export async function postGenerate(req: Request, res: Response): Promise<void> {
  const parsed = genSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Datos invalidos', details: parsed.error.flatten().fieldErrors });
    return;
  }
  try {
    const report = await generateReport({
      title: parsed.data.title,
      range: parsed.data.range,
      type: 'manual',
      userId: req.user!.id,
    });
    res.status(201).json({ report });
  } catch (err) {
    handle(err, res);
  }
}

export async function getList(_req: Request, res: Response): Promise<void> {
  try {
    res.json({ reports: await listReports() });
  } catch (err) {
    handle(err, res);
  }
}

export async function getDownload(req: Request, res: Response): Promise<void> {
  try {
    const { path, title } = await getReportFile(req.params.id);
    const safe = title.replace(/[^\w.-]+/g, '_').slice(0, 60);
    res.download(path, `${safe}.pdf`);
  } catch (err) {
    handle(err, res);
  }
}

export async function remove(req: Request, res: Response): Promise<void> {
  try {
    await deleteReport(req.params.id);
    res.json({ ok: true });
  } catch (err) {
    handle(err, res);
  }
}

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error('Error en reportes:', err);
  res.status(500).json({ error: 'Error generando el reporte' });
}
