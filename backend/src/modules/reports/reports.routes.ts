/**
 * Rutas del informe tecnico del SOC + dosier de auditoria. Requieren autenticacion.
 *   GET    /api/reports                  listado/historico
 *   GET    /api/reports/presets          periodos disponibles
 *   GET    /api/reports/dossier          dosier de auditoria (todo en uno, PDF)
 *   POST   /api/reports/generate         generar (admin|analista)
 *   GET    /api/reports/:id/preview      HTML para vista previa
 *   GET    /api/reports/:id/download     descargar PDF
 *   DELETE /api/reports/:id              borrar (admin|analista)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { postGenerate, getList, getPreview, getDownload, remove, getPresets } from './reports.controller';
import { buildDossier } from './dossier.service';
import { HttpError } from '../auth/auth.service';

export const reportsRouter = Router();
reportsRouter.use(authenticate);

const canManage = requireRole('admin', 'analista');

reportsRouter.get('/', getList);
reportsRouter.get('/presets', getPresets);

reportsRouter.get('/dossier', canManage, async (req: Request, res: Response) => {
  const preset = typeof req.query.preset === 'string' ? req.query.preset : undefined;
  const desde = typeof req.query.desde === 'string' ? req.query.desde : undefined;
  const hasta = typeof req.query.hasta === 'string' ? req.query.hasta : undefined;
  const tecnico = req.query.tecnico !== '0' && req.query.tecnico !== 'false';
  try {
    const { buffer, filename } = await buildDossier({ preset, desde, hasta }, { tecnico });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.send(buffer);
  } catch (err) {
    if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
    // eslint-disable-next-line no-console
    console.error('Error generando dosier de auditoria:', err);
    res.status(500).json({ error: 'Error generando el dosier de auditoría' });
  }
});

reportsRouter.post('/generate', canManage, postGenerate);
reportsRouter.get('/:id/preview', getPreview);
reportsRouter.get('/:id/download', getDownload);
reportsRouter.delete('/:id', canManage, remove);
