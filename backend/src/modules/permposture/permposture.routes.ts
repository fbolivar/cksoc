/**
 * Postura de Permisos / Compartición (M365).
 *   GET /api/permposture?days=30   invitados externos + compartición + recomendaciones
 */
import { Router, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { logger } from '../../config/logger';
import { getPosture } from './permposture.service';

export const permPostureRouter = Router();
permPostureRouter.use(authenticate);
const canView = requireRole('admin', 'analista');

permPostureRouter.get('/', canView, async (req, res: Response) => {
  try { const days = typeof req.query.days === 'string' ? req.query.days : '30d'; res.json(await getPosture(days)); }
  catch (e) { logger.error({ err: e }, 'Error en postura de permisos'); res.status(502).json({ error: 'No se pudo construir la postura de permisos' }); }
});
