/**
 * Rutas del modulo de notificaciones. Requieren autenticacion.
 * La gestion de reglas y pruebas se limita a admin/analista (lector solo ve).
 *
 *   GET    /api/notifications/rules
 *   POST   /api/notifications/rules            (admin|analista)
 *   GET    /api/notifications/rules/:id
 *   PUT    /api/notifications/rules/:id         (admin|analista)
 *   DELETE /api/notifications/rules/:id         (admin|analista)
 *   POST   /api/notifications/test             (admin|analista)
 *   GET    /api/notifications/channels/:channel/check  (admin|analista)
 *   POST   /api/notifications/evaluate         (admin|analista)
 *   GET    /api/notifications/log
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import {
  getRules,
  postRule,
  putRule,
  removeRule,
  getOneRule,
  postTest,
  getChannelCheck,
  postEvaluateNow,
  getLog,
} from './notifications.controller';

export const notificationsRouter = Router();
notificationsRouter.use(authenticate);

const canManage = requireRole('admin', 'analista');

notificationsRouter.get('/rules', getRules);
notificationsRouter.get('/rules/:id', getOneRule);
notificationsRouter.post('/rules', canManage, postRule);
notificationsRouter.put('/rules/:id', canManage, putRule);
notificationsRouter.delete('/rules/:id', canManage, removeRule);

notificationsRouter.post('/test', canManage, postTest);
notificationsRouter.get('/channels/:channel/check', canManage, getChannelCheck);
notificationsRouter.post('/evaluate', canManage, postEvaluateNow);
notificationsRouter.get('/log', getLog);
