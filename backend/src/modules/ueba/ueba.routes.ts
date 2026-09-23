/**
 * UEBA: anomalías de comportamiento de usuarios. Lectura para admin/analista;
 * gestionar estado (ack/descartar), ajustar configuración y forzar un escaneo
 * es sólo admin. Un scheduler corre el motor cada 15 min.
 */
import { Router, type Request, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';
import {
  scan, listAnomalies, countOpen, setStatus, entityProfile,
  getSettings, updateSettings, listEntities } from './ueba.service';

export const uebaRouter = Router();
uebaRouter.use(authenticate);

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  logger.error({ err }, 'Error en UEBA');
  res.status(500).json({ error: 'Error interno del servidor' });
}

uebaRouter.get('/entities', requireRole('admin', 'analista'), async (_req: Request, res: Response) => {
  try { res.json({ entities: await listEntities(7) }); } catch (err) { handle(err, res); }
});

uebaRouter.get('/anomalies', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const status = typeof req.query.status === 'string' ? req.query.status : 'open';
    const detector = typeof req.query.detector === 'string' ? req.query.detector : undefined;
    const days = req.query.days ? Number(req.query.days) : undefined;
    res.json({ open: await countOpen(), anomalies: await listAnomalies({ status, detector, days }) });
  } catch (err) { handle(err, res); }
});

uebaRouter.get('/entity/:user', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try { res.json(await entityProfile(String(req.params.user))); } catch (err) { handle(err, res); }
});

uebaRouter.post('/anomalies/:id/:decision', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const map: Record<string, 'open' | 'ack' | 'dismissed'> = { ack: 'ack', dismiss: 'dismissed', reopen: 'open' };
  const status = map[String(req.params.decision)];
  if (!status) { res.status(400).json({ error: 'decisión inválida' }); return; }
  try {
    const row = await setStatus(String(req.params.id), status, req.user!.id);
    if (!row) { res.status(404).json({ error: 'Anomalía no encontrada' }); return; }
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: `ueba_${status}`, target: row.entity, result: 'ok', detail: { detector: row.detector } });
    res.json(row);
  } catch (err) { handle(err, res); }
});

uebaRouter.get('/settings', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json(await getSettings()); } catch (err) { handle(err, res); }
});

uebaRouter.put('/settings', requireRole('admin'), async (req: Request, res: Response) => {
  try {
    const s = await updateSettings(req.body ?? {});
    void auditFromReq(req, { actorId: req.user!.id, actorEmail: req.user!.email, action: 'ueba_settings_update', target: 'ueba', result: 'ok', detail: s });
    res.json(s);
  } catch (err) { handle(err, res); }
});

// Fuerza un escaneo inmediato (para probar/actualizar bajo demanda).
uebaRouter.post('/scan', requireRole('admin'), async (_req, res) => {
  try { res.json(await scan()); } catch (err) { handle(err, res); }
});

/** Motor UEBA: escanea comportamiento cada 15 minutos. */
export function startUebaScheduler(): void {
  cron.schedule('*/15 * * * *', () => {
    scan()
      .then((r) => { if (r.anomalies) logger.info({ r }, 'UEBA: anomalías detectadas'); })
      .catch((err) => logger.warn({ err: err instanceof Error ? err.message : err }, 'UEBA: fallo en el escaneo'));
  });
}
