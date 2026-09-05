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

interface VeloClient { client_id?: string; host?: string; isolated?: boolean; last_seen_at?: number; system?: string }
interface VeloClientNorm extends VeloClient { online: boolean; lastSeenH: number | null; lastSeen: string | null }

// Un agente Velo cuenta como "vivo" si reportó en las últimas 24h.
const VELO_STALE_H = 24;

/**
 * Normaliza la lista cruda de Velociraptor:
 *  - de-duplica por host (una reinstalación deja 2 client_id; conservamos el de
 *    last_seen más reciente, que es el agente vivo y el objetivo correcto de triage).
 *  - calcula liveness real de Velo (online / hace cuántas horas) desde last_seen_at (µs).
 * Ordena: online primero, luego por visto más reciente.
 */
function normalizeClients(raw: unknown): VeloClientNorm[] {
  const list: VeloClient[] = Array.isArray(raw) ? raw : [];
  const now = Date.now();
  const byHost = new Map<string, VeloClient>();
  for (const c of list) {
    const host = String(c?.host || '').toLowerCase();
    if (!host) continue;
    const prev = byHost.get(host);
    if (!prev || (c.last_seen_at ?? 0) > (prev.last_seen_at ?? 0)) byHost.set(host, c);
  }
  const out: VeloClientNorm[] = [...byHost.values()].map((c) => {
    const ms = c.last_seen_at ? c.last_seen_at / 1000 : 0; // µs → ms
    const lastSeenH = ms ? (now - ms) / 3_600_000 : null;
    return {
      ...c,
      online: lastSeenH !== null && lastSeenH <= VELO_STALE_H,
      lastSeenH: lastSeenH === null ? null : Math.round(lastSeenH * 10) / 10,
      lastSeen: ms ? new Date(ms).toISOString() : null,
    };
  });
  out.sort((a, b) => Number(b.online) - Number(a.online) || (b.last_seen_at ?? 0) - (a.last_seen_at ?? 0));
  return out;
}

// Recomendaciones: hosts de alto riesgo (radar) para triage forense con Velociraptor.
velociraptorRouter.get('/recommendations', requireRole('admin', 'analista'), async (_req, res) => {
  try {
    const [radar, list] = await Promise.all([getAssetRadar(), runHelper(['list'])]);
    const clients = normalizeClients(list);
    const veloHosts = new Map<string, VeloClientNorm>();
    for (const c of clients) if (c.host) veloHosts.set(String(c.host).toLowerCase(), c);

    const items = radar.assets
      .filter((a) => a.band === 'critico' || a.band === 'alto')
      .map((a) => {
        const velo = veloHosts.get(a.name.toLowerCase());
        const hasVelo = Boolean(velo);
        const veloOnline = Boolean(velo?.online);
        const drivers: string[] = [];
        if (a.criticalVulns) drivers.push(`${a.criticalVulns} vulns críticas`);
        if (a.critAlerts) drivers.push(`${a.critAlerts} alertas críticas 24h`);
        if (a.highVulns && !a.criticalVulns) drivers.push(`${a.highVulns} vulns altas`);
        if (a.status !== 'active') drivers.push('agente Wazuh desconectado');
        // Estado operativo REAL para forense: ¿el agente Velo responde ahora?
        let accion: string;
        if (!hasVelo) accion = 'Sin agente Velociraptor: despliega el agente para poder investigar.';
        else if (!veloOnline) accion = `Agente Velociraptor desconectado${velo?.lastSeenH != null ? ` hace ${velo.lastSeenH} h` : ''}: no responderá al triage hasta que reconecte.`;
        else accion = 'Agente Velociraptor en línea: listo para recolectar evidencia (triage).';
        return {
          host: a.name, ip: a.ip, os: a.os, category: a.category, risk: a.risk, band: a.band, status: a.status,
          severity: a.band === 'critico' ? 'alta' : 'media',
          reason: `Riesgo ${a.risk}/100${drivers.length ? ' — ' + drivers.join(', ') : ''}. ${accion}`,
          hasVelo, veloOnline, veloLastSeenH: velo?.lastSeenH ?? null,
          triageable: veloOnline,
          isolated: velo?.isolated ?? false,
        };
      });
    // Prioriza lo accionable AHORA: triageable (Velo online) primero, luego por riesgo.
    items.sort((a, b) => Number(b.triageable) - Number(a.triageable) || b.risk - a.risk);
    res.json({ available: true, items, generatedAt: new Date().toISOString() });
  } catch (e) {
    res.status(502).json({ available: false, items: [], error: (e as Error).message });
  }
});

// Estado de la integración (para que el UI muestre/oculte el botón).
velociraptorRouter.get('/status', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['list']);
  if (Array.isArray(r)) {
    const clients = normalizeClients(r);
    res.json({ available: true, clients: clients.length, online: clients.filter((c) => c.online).length });
  } else res.json({ available: false, error: r?.error ?? 'no disponible' });
});

// Clientes Velociraptor (de-duplicados por host, con liveness real de Velo).
velociraptorRouter.get('/clients', requireRole('admin', 'analista'), async (_req, res) => {
  const r = await runHelper(['list']);
  if (Array.isArray(r)) res.json({ clients: normalizeClients(r) });
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
