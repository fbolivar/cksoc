/**
 * Rutas de Salud del SIEM.
 *   GET /api/health/siem      estado consolidado (semaforo + componentes + agentes)
 *   GET /api/health/history   bitacora de cambios (timeline de incidentes de salud)
 * Lectura para cualquier usuario autenticado.
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { query } from '../../config/db';
import { cachedHealth, refreshHealth } from './siem-health.service';

export const healthRouter = Router();

healthRouter.use(authenticate);

// Estado consolidado (sirve el cache que refresca el monitor; si no hay, calcula).
healthRouter.get('/siem', async (req: Request, res: Response) => {
  try {
    const force = req.query.refresh === '1';
    const data = !force && cachedHealth() ? cachedHealth() : await refreshHealth();
    res.json(data);
  } catch (err) {
    res.status(502).json({ error: err instanceof Error ? err.message : 'No se pudo consultar la salud del SIEM' });
  }
});

// Historico de cambios de estado (timeline).
healthRouter.get('/history', async (req: Request, res: Response) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  try {
    const rows = await query(
      `SELECT id, ts, componente, estado, detalle FROM health_log ORDER BY ts DESC LIMIT $1`,
      [limit]
    );
    res.json({ eventos: rows });
  } catch {
    res.status(500).json({ error: 'No se pudo consultar el histórico de salud' });
  }
});
