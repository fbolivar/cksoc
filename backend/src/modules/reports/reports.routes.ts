/**
 * Rutas del modulo de reportes. Requieren autenticacion.
 *   GET    /api/reports                 listado/historico
 *   POST   /api/reports/generate         generar (admin|analista)
 *   GET    /api/reports/:id/download      descargar PDF
 *   DELETE /api/reports/:id              borrar (admin|analista)
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { postGenerate, getList, getDownload, remove } from './reports.controller';

export const reportsRouter = Router();
reportsRouter.use(authenticate);

const canManage = requireRole('admin', 'analista');

reportsRouter.get('/', getList);
reportsRouter.post('/generate', canManage, postGenerate);
reportsRouter.get('/:id/download', getDownload);
reportsRouter.delete('/:id', canManage, remove);
