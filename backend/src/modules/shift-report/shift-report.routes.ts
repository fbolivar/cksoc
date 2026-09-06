/**
 * Rutas del Parte de Estado (shift report). Requieren autenticacion.
 *   GET  /api/shift-report/preview?turno=am|pm   HTML de vista previa
 *   GET  /api/shift-report/status                 estado (Telegram/destino)
 *   POST /api/shift-report/send                   generar y enviar (admin|analista)
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getPreview, getStatus, postSend } from './shift-report.controller';

export const shiftReportRouter = Router();
shiftReportRouter.use(authenticate);

shiftReportRouter.get('/preview', getPreview);
shiftReportRouter.get('/status', getStatus);
shiftReportRouter.post('/send', requireRole('admin', 'analista'), postSend);
