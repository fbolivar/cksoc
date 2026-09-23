/**
 * Reporte de postura del SonicWall.
 *   GET /api/fwposture/preview  HTML del informe (admin|analista)
 *   GET /api/fwposture/pdf      PDF del informe (admin|analista)
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { isFortigateConfigured } from '../response/fortigate.service';
import { generateFwPostureHtml } from './fwposture.service';
import { htmlToPdf } from '../reports/pdf.service';

export const fwpostureRouter = Router();
fwpostureRouter.use(authenticate);

const canRun = requireRole('admin', 'analista');

fwpostureRouter.get('/preview', canRun, async (req: Request, res: Response) => {
  if (!isFortigateConfigured()) { res.status(503).json({ error: 'SonicWall no configurado' }); return; }
  try {
    const { posture, html } = await generateFwPostureHtml();
    void auditFromReq(req, { actorId: req.user?.id, actorEmail: req.user?.email, action: 'fwposture_generate', target: posture.device.hostname, result: 'ok', detail: { score: posture.resumen.score, fail: posture.resumen.fail } });
    res.type('html').send(html);
  } catch (e) {
    res.status(502).json({ error: e instanceof Error ? e.message : 'No se pudo generar la postura del firewall' });
  }
});

fwpostureRouter.get('/pdf', canRun, async (req: Request, res: Response) => {
  if (!isFortigateConfigured()) { res.status(503).json({ error: 'SonicWall no configurado' }); return; }
  try {
    const { posture, html } = await generateFwPostureHtml();
    const pdf = await htmlToPdf(html);
    void auditFromReq(req, { actorId: req.user?.id, actorEmail: req.user?.email, action: 'fwposture_pdf', target: posture.device.hostname, result: 'ok', detail: { score: posture.resumen.score } });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="Postura_Firewall_${posture.device.hostname}_${posture.generatedAt.slice(0, 10)}.pdf"`);
    res.send(pdf);
  } catch (e) {
    res.status(502).json({ error: e instanceof Error ? e.message : 'No se pudo generar el PDF' });
  }
});
