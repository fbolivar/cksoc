/**
 * Rutas de Detección de Vulnerabilidades.
 *   GET  /api/vulnerabilities              resumen + priorizadas (KEV/EPSS) + lista
 *   GET  /api/vulnerabilities/intel        estado de los feeds CISA KEV / EPSS
 *   POST /api/vulnerabilities/intel/refresh fuerza refresco de KEV + EPSS (admin)
 */
import { Router, type Request, type Response } from 'express';
import cron from 'node-cron';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getVulnerabilities, invalidateCache } from './vuln.service';
import { intelStatus, refreshIntel, refreshKev, getEnvCves, enrichEpss } from './cveintel.service';
import { HttpError } from '../auth/auth.service';
import { logger } from '../../config/logger';

export const vulnRouter = Router();
vulnRouter.use(authenticate);

function handle(err: unknown, res: Response): void {
  if (err instanceof HttpError) { res.status(err.status).json({ error: err.message }); return; }
  res.status(500).json({ error: 'Error interno consultando vulnerabilidades' });
}

vulnRouter.get('/', async (_req: Request, res: Response) => {
  try { res.json(await getVulnerabilities()); } catch (err) { handle(err, res); }
});

vulnRouter.get('/intel', requireRole('admin', 'analista'), async (_req, res) => {
  try { res.json(await intelStatus()); } catch (err) { handle(err, res); }
});

vulnRouter.post('/intel/refresh', requireRole('admin'), async (_req, res) => {
  try {
    const r = await refreshIntel();
    invalidateCache();
    res.json({ ...r, ...(await intelStatus()) });
  } catch (err) { handle(err, res); }
});

/** Refresco programado de la inteligencia de CVEs. */
export function startCveIntelScheduler(): void {
  // CISA KEV: diario 04:10
  cron.schedule('10 4 * * *', () => {
    refreshKev().then(() => invalidateCache()).catch((e) => logger.warn({ err: e instanceof Error ? e.message : e }, 'KEV refresh falló'));
  });
  // EPSS de las CVEs del entorno: cada 6 h
  cron.schedule('20 */6 * * *', () => {
    getEnvCves().then((cves) => enrichEpss(cves)).then(() => invalidateCache())
      .catch((e) => logger.warn({ err: e instanceof Error ? e.message : e }, 'EPSS refresh falló'));
  });
  // Carga inicial ~30 s tras arrancar si aún no hay datos.
  setTimeout(() => {
    intelStatus().then((s) => {
      if (s.kevCount === 0 || s.epssCount === 0) {
        logger.info('CVE intel: carga inicial');
        refreshIntel().then(() => invalidateCache()).catch(() => undefined);
      }
    }).catch(() => undefined);
  }, 30_000);
}
