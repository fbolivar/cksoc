/**
 * Rutas del informe tecnico del SOC. Requieren autenticacion.
 *   GET    /api/reports                  listado/historico
 *   GET    /api/reports/presets          periodos disponibles
 *   POST   /api/reports/generate         generar (admin|analista)
 *   GET    /api/reports/:id/preview      HTML para vista previa
 *   GET    /api/reports/:id/download     descargar PDF
 *   DELETE /api/reports/:id              borrar (admin|analista)
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { postGenerate, getList, getPreview, getDownload, remove, getPresets } from './reports.controller';

export const reportsRouter = Router();
reportsRouter.use(authenticate);

const canManage = requireRole('admin', 'analista');

reportsRouter.get('/', getList);
reportsRouter.get('/presets', getPresets);
reportsRouter.post('/generate', canManage, postGenerate);
reportsRouter.get('/:id/preview', getPreview);
reportsRouter.get('/:id/download', getDownload);
reportsRouter.delete('/:id', canManage, remove);
