/**
 * Rutas de respuesta semi-automatica. Requieren autenticacion.
 * Bloquear/desbloquear: SOLO ADMIN. Ver incidentes/auditoria: admin + analista.
 *
 *   GET  /api/response/status               estado FortiGate + lista blanca
 *   GET  /api/response/incidents?hours=24    cola de incidentes enriquecida
 *   GET  /api/response/reputation/:ip        contexto de una IP (investigar)
 *   GET  /api/response/blocked               IPs bloqueadas por la app
 *   GET  /api/response/history               auditoria de acciones
 *   POST /api/response/block   { ip, motivo } (ADMIN) bloquear
 *   POST /api/response/unblock { ip }         (ADMIN) desbloquear
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import {
  postBlock,
  postUnblock,
  getBlocked,
  getHistory,
  getIncidentsCtrl,
  getReputation,
  getStatus,
} from './response.controller';

export const responseRouter = Router();
responseRouter.use(authenticate);

const viewers = requireRole('admin', 'analista');
const onlyAdmin = requireRole('admin');

responseRouter.get('/status', viewers, getStatus);
responseRouter.get('/incidents', viewers, getIncidentsCtrl);
responseRouter.get('/reputation/:ip', viewers, getReputation);
responseRouter.get('/blocked', viewers, getBlocked);
responseRouter.get('/history', viewers, getHistory);

// Acciones que modifican el FortiGate: SOLO ADMIN
responseRouter.post('/block', onlyAdmin, postBlock);
responseRouter.post('/unblock', onlyAdmin, postUnblock);
