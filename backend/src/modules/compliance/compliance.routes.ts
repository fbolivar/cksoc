/**
 * Rutas de Cumplimiento normativo.
 *   GET /api/compliance?hours=720            datos de cobertura por marco
 *   GET /api/compliance/report.pdf?hours=720 informe de cumplimiento (PDF con marca)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { getCompliance } from './compliance.service';
import { complianceReportPdf } from './compliance.report';
import { HttpError } from '../auth/auth.service';

export const complianceRouter = Router();
complianceRouter.use(authenticate);

function parseHours(q: unknown): number {
  const h = Number(q);
  return Number.isFinite(h) && h > 0 && h <= 2160 ? Math.floor(h) : 720;
}

complianceRouter.get('/', async (req: Request, res: Response) => {
  try {
    res.json(await getCompliance(parseHours(req.query.hours)));
  } catch (err) {
    if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
    res.status(500).json({ error: 'Error interno consultando cumplimiento' });
  }
});

complianceRouter.get('/report.pdf', async (req: Request, res: Response) => {
  try {
    const { buffer, filename } = await complianceReportPdf(parseHours(req.query.hours));
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (err) {
    if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
    // eslint-disable-next-line no-console
    console.error('Error generando informe de cumplimiento:', err);
    res.status(500).json({ error: 'Error generando el informe de cumplimiento' });
  }
});
