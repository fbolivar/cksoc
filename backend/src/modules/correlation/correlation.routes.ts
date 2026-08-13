/**
 * Correlación multi-fuente: casos agrupados por IP de origen (solo lectura).
 * La creación del incidente unificado la hace el frontend vía el módulo de
 * incidentes existente, con el contexto de la correlación.
 */
import { Router } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import { getCorrelations } from './correlation.service';

export const correlationRouter = Router();
correlationRouter.use(authenticate);

correlationRouter.get('/', requireRole('admin', 'analista'), async (req, res) => {
  const range = typeof req.query.range === 'string' ? req.query.range : '24h';
  try {
    res.json({ range, correlations: await getCorrelations(range) });
  } catch (err) {
    if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
    logger.error({ err }, 'Error en correlación');
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});
