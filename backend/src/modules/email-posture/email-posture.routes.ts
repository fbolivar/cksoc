/**
 * Postura de correo (SPF / DKIM / DMARC / MX) + reportes DMARC agregados.
 *   GET /api/email-posture?domain=ejemplo.com   → postura por dominio (DNS en vivo)
 *   GET /api/email-posture/dmarc?days=14         → reportes DMARC (rua) vía Graph
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { getPosture, dmarcReadiness, getDmarcReports } from './email-posture.service';

export const emailPostureRouter = Router();
emailPostureRouter.use(authenticate);

emailPostureRouter.get('/', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const domains = typeof req.query.domain === 'string' && req.query.domain.trim()
      ? [req.query.domain.trim().toLowerCase()] : undefined;
    const [posture, readiness] = await Promise.all([getPosture(domains), dmarcReadiness()]);
    res.json({ domains: posture, dmarcReadiness: readiness, generatedAt: new Date().toISOString() });
  } catch (err) {
    res.status(502).json({ error: (err as { message?: string }).message ?? 'No se pudo evaluar la postura de correo' });
  }
});

emailPostureRouter.get('/dmarc', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  try {
    const days = Math.min(90, Math.max(1, Number(req.query.days) || 14));
    res.json(await getDmarcReports(days));
  } catch (err) {
    res.status(502).json({ error: (err as { message?: string }).message ?? 'No se pudieron leer los reportes DMARC' });
  }
});
