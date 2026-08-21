/**
 * Integración con Velociraptor (DFIR): permite lanzar colecciones/hunts en un
 * host desde HexWatch y listar los clientes. Llama a un helper Python que habla
 * con la API de Velociraptor (gRPC/mTLS) vía pyvelociraptor.
 */
import { Router, type Request, type Response } from 'express';
import { authenticate } from '../../middleware/auth';
import { requireRole } from '../../middleware/roles';
import { auditFromReq } from '../audit/audit.service';
import { runHelper } from './velociraptor.helper';
import { getAssetRadar } from '../overview/radar.service';

export const velociraptorRouter = Router();

velociraptorRouter.use(authenticate);

interface VeloClient { client_id?: string; host?: string; isolated?: boolean }

// Recomendaciones: hosts de alto riesgo (radar) para triage forense con Velociraptor.
velociraptorRouter.get('/recommendations', requireRole('admin', 'analista'), async (_req, res) => {
  try {
    const [radar, list] = await Promise.all([getAssetRadar(), runHelper(['list'])]);
    const clients: VeloClient[] = Array.isArray(list) ? list : [];
    const veloHosts = new Map<string, { clientId: string; isolated: boolean }>();
    for (const c of clients) if (c?.host) veloHosts.set(String(c.host).toLowerCase(), { clientId: c.client_id ?? '', isolated: Boolean(c.isolated) });

    const items = radar.assets
      .filter((a) => a.band === 'critico' || a.band === 'alto')
      .map((a) => {
        const velo = veloHosts.get(a.name.toLowerCase());
        const drivers: string[] = [];
        if (a.criticalVulns) drivers.push(`${a.criticalVulns} vulns críticas`);
        if (a.critAlerts) drivers.push(`${a.critAlerts} alertas críticas 24h`);
        if (a.highVulns && !a.criticalVulns) drivers.push(`${a.highVulns} vulns altas`);
        if (a.status !== 'active') drivers.push('agente desconectado');
        return {
          host: a.name, ip: a.ip, os: a.os, category: a.category, risk: a.risk, band: a.band, status: a.status,
          severity: a.band === 'critico' ? 'alta' : 'media',
          reason: `Riesgo ${a.risk}/100${drivers.length ? ' — ' + drivers.join(', ') : ''}. Recolecta evidencia forense (triage) para investigar.`,
          hasVelo: Boolean(velo), isolated: velo?.isolated ?? false,
        };
      });
    res.json({ available: true, items, generatedAt: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ available: false, items: [], error: (e as Error).message });
  }
});

// Estado de la integración (para que el UI muestre/oculte el botón).
velociraptorRouter.get('/status', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['list']);
  if (Array.isArray(r)) res.json({ available: true, clients: r.length });
  else res.json({ available: false, error: r?.error ?? 'no disponible' });
});

// Clientes Velociraptor.
velociraptorRouter.get('/clients', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['list']);
  if (Array.isArray(r)) res.json({ clients: r });
  else res.status(502).json(r);
});

// Colecciones (flows) recientes de un cliente.
velociraptorRouter.get('/clients/:clientId/flows', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const clientId = String(req.params.clientId || '');
  if (!/^C\.[0-9a-f]{6,32}$/i.test(clientId)) {
    res.status(400).json({ error: 'client_id inválido' });
    return;
  }
  const r = await runHelper(['flows', clientId]);
  if (r?.error) { res.status(502).json(r); return; }
  res.json(r); // { client_id, flows: [...] }
});

// Catálogo de artefactos de cliente (para elegir qué recolectar).
velociraptorRouter.get('/artifacts', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['artifacts']);
  if (r?.error) { res.status(502).json(r); return; }
  res.json(r); // { artifacts: [{name, description}] }
});

// Resultados (filas) de una colección concreta.
velociraptorRouter.get('/clients/:clientId/flows/:flowId/results', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const clientId = String(req.params.clientId || '');
  const flowId = String(req.params.flowId || '');
  if (!/^C\.[0-9a-f]{6,32}$/i.test(clientId) || !/^F\.[0-9A-Za-z]{6,40}$/.test(flowId)) {
    res.status(400).json({ error: 'client_id o flow_id inválido' });
    return;
  }
  const r = await runHelper(['results', clientId, flowId]);
  if (r?.error) { res.status(502).json(r); return; }
  res.json(r); // { client_id, flow_id, sources: [{artifact, columns, count, rows}] }
});

// Contención de endpoint: aislar / liberar / triage rápido.
// Aislar y liberar son disruptivos (cortan la red del host salvo Velociraptor):
// solo admin. Triage (recolección) lo puede lanzar también un analista.
velociraptorRouter.post('/action', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const host = String(req.body?.host || '').trim();
  const action = String(req.body?.action || '').trim();
  if (!host || !/^[A-Za-z0-9._-]{1,120}$/.test(host)) { res.status(400).json({ error: 'host inválido' }); return; }
  if (!['isolate', 'release', 'triage'].includes(action)) { res.status(400).json({ error: 'acción inválida' }); return; }
  if ((action === 'isolate' || action === 'release') && req.user!.role !== 'admin') {
    res.status(403).json({ error: 'Aislar/liberar un endpoint requiere rol admin' });
    return;
  }
  const r = await runHelper(['action', host, action]);
  if (r?.error) { res.status(502).json(r); return; }
  void auditFromReq(req, {
    actorId: req.user!.id, actorEmail: req.user!.email,
    action: `velociraptor_${action}`, target: host, result: 'ok',
    detail: { flow_id: r.flow_id, client_id: r.client_id },
  });
  res.json(r);
});

// Lanzar colección forense en un host.
velociraptorRouter.post('/collect', requireRole('admin', 'analista'), async (req: Request, res: Response) => {
  const host = String(req.body?.host || '').trim();
  if (!host || !/^[A-Za-z0-9._-]{1,120}$/.test(host)) {
    res.status(400).json({ error: 'host inválido' });
    return;
  }
  // Artefacto opcional (p.ej. Windows.System.Pslist); por defecto Generic.Client.Info.
  const artifact = String(req.body?.artifact || '').trim();
  if (artifact && !/^[A-Za-z0-9._]{1,120}$/.test(artifact)) {
    res.status(400).json({ error: 'artefacto inválido' });
    return;
  }
  const r = await runHelper(artifact ? ['collect', host, artifact] : ['collect', host]);
  if (r?.error) {
    res.status(502).json(r);
    return;
  }
  void auditFromReq(req, {
    actorId: req.user!.id, actorEmail: req.user!.email,
    action: 'velociraptor_collect', target: host, result: 'ok',
    detail: { flow_id: r.flow_id, client_id: r.client_id, artifacts: r.artifacts },
  });
  res.json(r);
});
